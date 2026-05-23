#!/usr/bin/env python3
"""cbom_diff.py 단위 테스트 — TLS 검증 키워드 추출 및 매칭 로직."""

import os
import sys
import unittest
from unittest.mock import patch

# 프로젝트 루트에서 pytest 실행 시에도 policy/ 모듈을 import 할 수 있도록
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cbom_diff import (
    _build_handshake_cmd,
    _cipher_to_keywords,
    _extract_cbom_algorithms,
    _match_keyword_in_cbom,
    _normalize,
    _parse_handshake_output,
    _run_tls_handshake,
    get_property,
    set_property,
    verify_tls_against_cbom,
)


class TestNormalize(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(_normalize("AES-256-GCM"), "aes256gcm")

    def test_underscores(self):
        self.assertEqual(_normalize("AES_256_GCM"), "aes256gcm")

    def test_mixed(self):
        self.assertEqual(_normalize("ML-KEM-768"), "mlkem768")

    def test_already_normalized(self):
        self.assertEqual(_normalize("sha384"), "sha384")


class TestCipherToKeywords(unittest.TestCase):
    def test_tls13_aes_gcm(self):
        kws = _cipher_to_keywords("TLS_AES_256_GCM_SHA384", "X25519")
        self.assertIn("AES-256-GCM", kws)
        self.assertIn("SHA384", kws)
        self.assertIn("X25519", kws)

    def test_tls13_chacha20(self):
        kws = _cipher_to_keywords("TLS_CHACHA20_POLY1305_SHA256", "X25519")
        self.assertIn("ChaCha20-Poly1305", kws)
        self.assertIn("SHA256", kws)

    def test_chacha20_standalone(self):
        kws = _cipher_to_keywords("CHACHA20", "")
        self.assertIn("ChaCha20", kws)
        self.assertNotIn("ChaCha20-Poly1305", kws)

    def test_ecdhe_rsa(self):
        kws = _cipher_to_keywords("ECDHE_RSA_AES_128_GCM_SHA256", "P256")
        self.assertIn("ECDHE", kws)
        self.assertIn("RSA", kws)
        self.assertIn("AES-128-GCM", kws)
        # cbom_gen.py 는 P-curve 그룹을 ECDH-P-{N} 으로 정규화하므로
        # 두 형태 모두 키워드에 포함돼야 한다.
        self.assertIn("P-256", kws)
        self.assertIn("ECDH-P-256", kws)

    def test_mlkem_hybrid(self):
        kws = _cipher_to_keywords("TLS_AES_256_GCM_SHA384", "X25519MLKEM768")
        self.assertIn("ML-KEM-768", kws)
        self.assertIn("X25519", kws)

    def test_empty(self):
        self.assertEqual(_cipher_to_keywords("", ""), [])

    def test_p384_group(self):
        kws = _cipher_to_keywords("TLS_AES_128_GCM_SHA256", "P384")
        self.assertIn("P-384", kws)
        self.assertIn("ECDH-P-384", kws)

    def test_p521_group(self):
        kws = _cipher_to_keywords("TLS_AES_256_GCM_SHA384", "P521")
        self.assertIn("P-521", kws)
        self.assertIn("ECDH-P-521", kws)

    def test_secp_aliases(self):
        """openssl 이 secp256r1/secp384r1/secp521r1 형태로 보고하는 케이스."""
        self.assertIn("ECDH-P-256",
                      _cipher_to_keywords("TLS_AES_128_GCM_SHA256", "secp256r1"))
        self.assertIn("ECDH-P-384",
                      _cipher_to_keywords("TLS_AES_128_GCM_SHA256", "secp384r1"))
        self.assertIn("ECDH-P-521",
                      _cipher_to_keywords("TLS_AES_128_GCM_SHA256", "secp521r1"))


class TestMatchKeyword(unittest.TestCase):
    def test_exact_match(self):
        cbom_norm = {_normalize("AES-256-GCM"), _normalize("SHA384")}
        self.assertTrue(_match_keyword_in_cbom("AES-256-GCM", cbom_norm))

    def test_different_separator(self):
        cbom_norm = {_normalize("AES-256-GCM")}
        # AES_256_GCM normalizes to same as AES-256-GCM
        self.assertTrue(_match_keyword_in_cbom("AES_256_GCM", cbom_norm))

    def test_no_match(self):
        cbom_norm = {_normalize("AES-128-GCM")}
        self.assertFalse(_match_keyword_in_cbom("AES-256-GCM", cbom_norm))

    def test_no_partial_match(self):
        """'SHA256'이 'SHA2560' 같은 것에 매칭되면 안 됨."""
        cbom_norm = {_normalize("SHA2560")}
        self.assertFalse(_match_keyword_in_cbom("SHA256", cbom_norm))


class TestExtractCbomAlgorithms(unittest.TestCase):
    def test_extracts_algorithms(self):
        bom = {"components": [
            {"name": "AES-256-GCM", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "some-cert", "cryptoProperties": {"assetType": "certificate"}},
            {"name": "ML-KEM-768", "cryptoProperties": {"assetType": "algorithm"}},
        ]}
        algos = _extract_cbom_algorithms(bom)
        self.assertEqual(algos, {"AES-256-GCM", "ML-KEM-768"})

    def test_empty_bom(self):
        self.assertEqual(_extract_cbom_algorithms({}), set())


class TestVerifyTlsAgainstCbom(unittest.TestCase):
    @patch("cbom_diff._run_tls_handshake")
    def test_pass(self, mock_hs):
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519",
        }
        bom = {"components": [
            {"name": "AES-256-GCM", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "SHA384", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "X25519", "cryptoProperties": {"assetType": "algorithm"}},
        ]}
        result = verify_tls_against_cbom(bom, "localhost", 443)
        self.assertEqual(result["status"], "PASS")

    @patch("cbom_diff._run_tls_handshake")
    def test_mismatch(self, mock_hs):
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519",
        }
        bom = {"components": [
            {"name": "AES-256-GCM", "cryptoProperties": {"assetType": "algorithm"}},
            # SHA384, X25519 누락
        ]}
        result = verify_tls_against_cbom(bom, "localhost", 443)
        self.assertEqual(result["status"], "MISMATCH")
        self.assertIn("SHA384", result["missing_in_cbom"])

    @patch("cbom_diff._run_tls_handshake")
    def test_skipped(self, mock_hs):
        mock_hs.return_value = None
        result = verify_tls_against_cbom({}, "localhost", 443)
        self.assertEqual(result["status"], "SKIPPED")


class TestParseHandshakeOutput(unittest.TestCase):
    """openssl s_client -brief 출력 파싱 안전성 (콜론 없는 라인 등)."""

    def test_normal_output(self):
        out = (
            "Connecting to ...\n"
            "Protocol version: TLSv1.3\n"
            "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
            "Server Temp Key: X25519, 253 bits\n"
        )
        r = _parse_handshake_output(out)
        self.assertEqual(r["protocol"], "TLSv1.3")
        self.assertEqual(r["cipher"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(r["group"], "X25519")

    def test_lines_without_colon_do_not_raise(self):
        """콜론 없는 라인이 섞여 있어도 IndexError 안 터져야 함."""
        out = (
            "---\n"
            "DONE\n"
            "Protocol version: TLSv1.3\n"
            "noise without colon\n"
            "Ciphersuite: TLS_CHACHA20_POLY1305_SHA256\n"
        )
        r = _parse_handshake_output(out)  # 예외 없이 통과해야 함
        self.assertEqual(r["protocol"], "TLSv1.3")
        self.assertEqual(r["cipher"], "TLS_CHACHA20_POLY1305_SHA256")

    def test_pqc_hybrid_group(self):
        out = "Server Temp Key: X25519MLKEM768, 1216 bits\n"
        r = _parse_handshake_output(out)
        self.assertEqual(r["group"], "X25519MLKEM768")

    def test_empty_output(self):
        self.assertEqual(_parse_handshake_output(""), {})


class TestBuildHandshakeCmd(unittest.TestCase):
    """로컬/컨테이너 모드별 명령 구성."""

    @patch("cbom_diff.shutil.which", return_value="/usr/bin/openssl")
    def test_local_mode(self, _which):
        cmd = _build_handshake_cmd("proxy-server", 443, exec_container=None)
        self.assertEqual(cmd[0], "/usr/bin/openssl")
        self.assertIn("s_client", cmd)
        self.assertIn("-connect", cmd)
        self.assertIn("proxy-server:443", cmd)

    @patch("cbom_diff.shutil.which", return_value="/usr/bin/docker")
    def test_container_mode_uses_docker_exec(self, _which):
        cmd = _build_handshake_cmd("proxy-server", 443,
                                    exec_container="tls-tester")
        self.assertEqual(cmd[0], "/usr/bin/docker")
        self.assertEqual(cmd[1], "exec")
        self.assertEqual(cmd[2], "tls-tester")
        self.assertEqual(cmd[3], "openssl")
        self.assertIn("s_client", cmd)
        self.assertIn("proxy-server:443", cmd)

    @patch("cbom_diff.shutil.which", return_value=None)
    def test_local_mode_returns_none_when_openssl_missing(self, _which):
        self.assertIsNone(
            _build_handshake_cmd("h", 1, exec_container=None))

    @patch("cbom_diff.shutil.which", return_value=None)
    def test_container_mode_returns_none_when_docker_missing(self, _which):
        self.assertIsNone(
            _build_handshake_cmd("h", 1, exec_container="x"))


class TestRunTlsHandshakeContainerMode(unittest.TestCase):
    """_run_tls_handshake 의 컨테이너 모드 통합 검증 (subprocess mock)."""

    @patch("cbom_diff.subprocess.run")
    @patch("cbom_diff.shutil.which", return_value="/usr/bin/docker")
    def test_invokes_docker_exec(self, _which, mock_run):
        class _R:
            stdout = ("Protocol version: TLSv1.3\n"
                      "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
                      "Server Temp Key: X25519MLKEM768, 1216 bits\n")
            stderr = ""
        mock_run.return_value = _R()

        result = _run_tls_handshake("proxy-server", 443,
                                    exec_container="tls-tester")
        # 결과 파싱 정상
        self.assertEqual(result["protocol"], "TLSv1.3")
        self.assertEqual(result["cipher"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(result["group"], "X25519MLKEM768")
        # docker exec 명령으로 호출됐는지
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[:4],
                         ["/usr/bin/docker", "exec", "tls-tester", "openssl"])


class TestVerifyTlsExecContainerPassThrough(unittest.TestCase):
    """verify_tls_against_cbom 가 exec_container 를 _run_tls_handshake 에 잘 넘기는지."""

    @patch("cbom_diff._run_tls_handshake")
    def test_exec_container_passed_through(self, mock_hs):
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519MLKEM768",
        }
        bom = {"components": [
            {"name": "AES-256-GCM", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "SHA384", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "X25519", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "ML-KEM-768", "cryptoProperties": {"assetType": "algorithm"}},
        ]}
        result = verify_tls_against_cbom(bom, "proxy-server", 443,
                                         exec_container="tls-tester")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["exec_container"], "tls-tester")
        # _run_tls_handshake 가 exec_container 인자를 받았는지
        _, kwargs = mock_hs.call_args
        self.assertEqual(kwargs.get("exec_container"), "tls-tester")


class TestStageTlsGroupEnforcement(unittest.TestCase):
    """Stage 정책별 -groups 강제 동작 검증."""

    @patch("cbom_diff.shutil.which", return_value="/usr/bin/openssl")
    def test_stage2_forces_hybrid_group(self, _which):
        cmd = _build_handshake_cmd("h", 1, exec_container=None,
                                    tls_groups="X25519MLKEM768")
        self.assertIn("-groups", cmd)
        idx = cmd.index("-groups")
        self.assertEqual(cmd[idx + 1], "X25519MLKEM768")

    @patch("cbom_diff.shutil.which", return_value="/usr/bin/docker")
    def test_stage3_forces_mlkem1024_in_container_mode(self, _which):
        cmd = _build_handshake_cmd("h", 1, exec_container="tls-tester",
                                    tls_groups="mlkem1024")
        self.assertIn("-groups", cmd)
        idx = cmd.index("-groups")
        self.assertEqual(cmd[idx + 1], "mlkem1024")
        # docker exec 명령 구조 보존
        self.assertEqual(cmd[:4],
                         ["/usr/bin/docker", "exec", "tls-tester", "openssl"])

    @patch("cbom_diff.shutil.which", return_value="/usr/bin/openssl")
    def test_no_groups_when_unspecified(self, _which):
        """tls_groups 없으면 -groups 인자 자체가 cmd 에 없어야 함."""
        cmd = _build_handshake_cmd("h", 1, exec_container=None)
        self.assertNotIn("-groups", cmd)

    @patch("cbom_diff._run_tls_handshake")
    def test_verify_passes_stage_group_through(self, mock_hs):
        """verify_tls_against_cbom(tls_stage='2') → tls_groups='X25519MLKEM768' 전달."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519MLKEM768",
        }
        bom = {"components": [
            {"name": "AES-256-GCM", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "SHA384", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "X25519", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "ML-KEM-768", "cryptoProperties": {"assetType": "algorithm"}},
        ]}
        result = verify_tls_against_cbom(bom, "proxy-server", 443,
                                         exec_container="tls-tester",
                                         tls_stage="2")
        # stage / enforced_groups 결과 dict 에 기록되는지
        self.assertEqual(result["stage"], "2")
        self.assertEqual(result["enforced_groups"], "X25519MLKEM768")
        # _run_tls_handshake 에 tls_groups 인자가 전달됐는지
        _, kwargs = mock_hs.call_args
        self.assertEqual(kwargs.get("tls_groups"), "X25519MLKEM768")

    @patch("cbom_diff._run_tls_handshake")
    def test_verify_stage1_no_group_enforcement(self, mock_hs):
        """Stage 1 은 STAGE_TLS_GROUPS 매핑에 없으므로 group 강제 안 함."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519",
        }
        bom = {"components": [
            {"name": "AES-256-GCM", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "SHA384", "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "X25519", "cryptoProperties": {"assetType": "algorithm"}},
        ]}
        result = verify_tls_against_cbom(bom, "proxy-server", 443,
                                         exec_container="tls-tester",
                                         tls_stage="1")
        self.assertEqual(result["stage"], "1")
        self.assertNotIn("enforced_groups", result)
        _, kwargs = mock_hs.call_args
        self.assertIsNone(kwargs.get("tls_groups"))


def _stage2_bom():
    """BOM 이 Stage 2 PQC 를 클레임하는 fixture (pqc_status property + 컴포넌트)."""
    return {
        "properties": [
            {"name": "securecapstone:pqc_status",
             "value": "STAGE_2_HYBRID_PQC"},
        ],
        "components": [
            {"name": "AES-256-GCM",
             "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "SHA384",
             "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "X25519",
             "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "X25519MLKEM768",
             "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "ML-KEM-768",
             "cryptoProperties": {"assetType": "algorithm"}},
        ],
    }


class TestStageDowngradeDetection(unittest.TestCase):
    """BOM 의 pqc_status 클레임 대비 실제 핸드셰이크 다운그레이드 감지.

    이 게이트가 없으면 OQS provider 가 런타임에 죽어 클래식으로 fallback 한
    상황이 keyword superset 체크만으로는 PASS 떨어진다 — silent false PASS.
    """

    @patch("cbom_diff._run_tls_handshake")
    def test_classical_fallback_under_stage2_bom_is_downgrade(self, mock_hs):
        """BOM Stage 2 클레임 + 실제 협상은 클래식 X25519 → DOWNGRADE_DETECTED.
        사용자가 --tls-stage 안 박았어도 BOM 에서 default 로 stage 추론."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519",  # 클래식 — MLKEM 없음
        }
        # tls_stage 명시 안 함 — BOM 의 pqc_status 에서 추론되어야 함
        result = verify_tls_against_cbom(
            _stage2_bom(), "proxy-server", 443, tls_stage=None)
        self.assertEqual(result["status"], "DOWNGRADE_DETECTED")
        self.assertEqual(result["stage"], "2")
        self.assertEqual(result["stage_source"], "bom")
        # detail 에 negotiated stage 분류 결과가 포함되어야 함
        self.assertIn("STAGE_1_CLASSICAL", result["detail"])

    @patch("cbom_diff._run_tls_handshake")
    def test_tls12_under_stage2_is_downgrade(self, mock_hs):
        """Stage 2 + TLS 1.2 협상 → DOWNGRADE_DETECTED. ML-KEM key_share 는
        TLS 1.3 전용이므로 1.2 다운그레이드는 PQC 비활성 시그널."""
        mock_hs.return_value = {
            "protocol": "TLSv1.2",
            "cipher": "TLS_AES_256_GCM_SHA384",
            # 어떤 이유로 group 이름엔 MLKEM 박혀있지만 protocol 이 1.2
            "group": "X25519MLKEM768",
        }
        result = verify_tls_against_cbom(
            _stage2_bom(), "proxy-server", 443, tls_stage="2")
        self.assertEqual(result["status"], "DOWNGRADE_DETECTED")
        self.assertIn("TLS 1.3", result["detail"])

    @patch("cbom_diff._run_tls_handshake")
    def test_legit_stage2_handshake_passes(self, mock_hs):
        """정상 Stage 2 협상 (TLS 1.3 + X25519MLKEM768) → PASS."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519MLKEM768",
        }
        result = verify_tls_against_cbom(
            _stage2_bom(), "proxy-server", 443, tls_stage="2")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["stage_source"], "cli")

    @patch("cbom_diff._run_tls_handshake")
    def test_cli_stage_overrides_bom(self, mock_hs):
        """--tls-stage 가 BOM 보다 우선. stage_source='cli' 표시."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519MLKEM768",
        }
        result = verify_tls_against_cbom(
            _stage2_bom(), "proxy-server", 443, tls_stage="3")
        self.assertEqual(result["stage"], "3")
        self.assertEqual(result["stage_source"], "cli")

    @patch("cbom_diff._run_tls_handshake")
    def test_stage1_classical_handshake_passes(self, mock_hs):
        """Stage 1 클레임 + 클래식 협상 → 정상 PASS (다운그레이드 개념 없음)."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519",
        }
        bom = {
            "properties": [
                {"name": "securecapstone:pqc_status",
                 "value": "STAGE_1_CLASSICAL"},
            ],
            "components": [
                {"name": "AES-256-GCM",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "SHA384",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "X25519",
                 "cryptoProperties": {"assetType": "algorithm"}},
            ],
        }
        result = verify_tls_against_cbom(bom, "proxy-server", 443,
                                          tls_stage=None)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["stage"], "1")
        self.assertEqual(result["stage_source"], "bom")

    @patch("cbom_diff._run_tls_handshake")
    def test_stage3_rejects_stage2_hybrid_group(self, mock_hs):
        """Stage 3 BOM 클레임 + 핸드셰이크는 Stage 2 hybrid (X25519MLKEM768)
        로 떨어진 경우 — DOWNGRADE_DETECTED. 과거 _assess_stage_compliance
        가 'MLKEM in group' 만 보고 stage 구분 못 해 false PASS 던 회귀."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519MLKEM768",  # Stage 2 hybrid — Stage 3 클레임에 못 미침
        }
        bom = {
            "properties": [
                {"name": "securecapstone:pqc_status",
                 "value": "STAGE_3_POST_QUANTUM"},
            ],
            "components": [
                {"name": "AES-256-GCM",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "SHA384",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "X25519MLKEM768",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "ML-KEM-768",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "ML-KEM-1024",
                 "cryptoProperties": {"assetType": "algorithm"}},
            ],
        }
        result = verify_tls_against_cbom(bom, "proxy-server", 443,
                                          tls_stage=None)
        self.assertEqual(result["status"], "DOWNGRADE_DETECTED")
        self.assertEqual(result["stage"], "3")
        self.assertIn("Stage 2", result["detail"])

    @patch("cbom_diff._run_tls_handshake")
    def test_stage3_accepts_p_curve_mlkem_hybrid(self, mock_hs):
        """Stage 3 클레임 + p384_mlkem768 (PURE_PQC 분류 = Stage 3) 협상
        → PASS. P-curve + MLKEM 은 Stage 3 정의에 포함됨."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "p384_mlkem768",
        }
        # _cipher_to_keywords 가 P-curve 에 대해 P-{N} + ECDH-P-{N} 둘 다
        # 키워드로 내므로 BOM 도 둘 다 들어있어야 keyword superset 체크 통과.
        bom = {
            "properties": [
                {"name": "securecapstone:pqc_status",
                 "value": "STAGE_3_POST_QUANTUM"},
            ],
            "components": [
                {"name": "AES-256-GCM",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "SHA384",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "P-384",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "ECDH-P-384",
                 "cryptoProperties": {"assetType": "algorithm"}},
                {"name": "ML-KEM-768",
                 "cryptoProperties": {"assetType": "algorithm"}},
            ],
        }
        result = verify_tls_against_cbom(bom, "proxy-server", 443,
                                          tls_stage="3")
        self.assertEqual(result["status"], "PASS")

    @patch("cbom_diff._run_tls_handshake")
    def test_cli_bom_stage_disagreement_surfaces_warning(self, mock_hs):
        """--tls-stage 3 + BOM pqc_status=STAGE_2_HYBRID_PQC — CLI 우선이지만
        BOM 클레임도 result['bom_stage'] / 'stage_disagreement' 로 surface."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "p384_mlkem768",
        }
        result = verify_tls_against_cbom(
            _stage2_bom(), "proxy-server", 443, tls_stage="3")
        self.assertEqual(result["stage"], "3")
        self.assertEqual(result["stage_source"], "cli")
        self.assertEqual(result["bom_stage"], "2")
        self.assertIn("stage_disagreement", result)

    @patch("cbom_diff._run_tls_handshake")
    def test_no_bom_stage_no_downgrade_check(self, mock_hs):
        """BOM 에 pqc_status 없고 --tls-stage 도 없으면 stage 게이트는 비활성.
        keyword superset 체크만 동작 (기존 호환)."""
        mock_hs.return_value = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "group": "X25519",
        }
        bom = {"components": [
            {"name": "AES-256-GCM",
             "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "SHA384",
             "cryptoProperties": {"assetType": "algorithm"}},
            {"name": "X25519",
             "cryptoProperties": {"assetType": "algorithm"}},
        ]}
        result = verify_tls_against_cbom(bom, "proxy-server", 443,
                                          tls_stage=None)
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn("stage", result)


class TestSetPropertyRoundTrip(unittest.TestCase):
    """set_property / get_property 라운드트립 비대칭 회귀 가드.

    과거: set_property(bom, name, None) 이 str(None) = 'None' 으로 박혀
    get_property 가 문자열 'None' 을 돌려줬다 (None ≠ 'None'). make_property
    의 prune_none 동작과도 불일치. None 은 emit skip 으로 통일."""

    def test_none_value_skipped(self):
        bom = {}
        set_property(bom, "securecapstone:x", None)
        # property 자체가 박히면 안 됨
        props = bom.get("properties", [])
        self.assertEqual(props, [])
        # get_property 도 None 반환 (property 부재의 자연스러운 결과)
        self.assertIsNone(get_property(bom, "securecapstone:x"))

    def test_dict_round_trip(self):
        bom = {}
        original = {"stage": "2", "consistent": True}
        set_property(bom, "securecapstone:x", original)
        self.assertEqual(get_property(bom, "securecapstone:x"), original)

    def test_list_round_trip(self):
        bom = {}
        set_property(bom, "securecapstone:y", ["a", "b", "c"])
        self.assertEqual(get_property(bom, "securecapstone:y"), ["a", "b", "c"])

    def test_string_pqc_status_round_trip(self):
        """STAGE_*_* 같은 사용 빈도 높은 string 값은 그대로 보존."""
        bom = {}
        set_property(bom, "securecapstone:pqc_status", "STAGE_2_HYBRID_PQC")
        self.assertEqual(
            get_property(bom, "securecapstone:pqc_status"),
            "STAGE_2_HYBRID_PQC")

    def test_overwrite_existing(self):
        bom = {}
        set_property(bom, "securecapstone:x", "a")
        set_property(bom, "securecapstone:x", "b")
        self.assertEqual(get_property(bom, "securecapstone:x"), "b")
        # 중복 entry 박히면 안 됨
        self.assertEqual(
            sum(1 for p in bom["properties"]
                if p["name"] == "securecapstone:x"), 1)


if __name__ == "__main__":
    unittest.main()
