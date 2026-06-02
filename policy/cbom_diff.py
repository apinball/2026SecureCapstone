#!/usr/bin/env python3
"""
cbom_diff.py — CycloneDX CBOM 마이그레이션 이력 비교 및 TLS 스택 교차 검증

이전 실행의 CycloneDX CBOM과 현재 CBOM을 비교하여
migration_progress 정보를 properties에 추가합니다.
--verify-tls 사용 시 실제 TLS 핸드셰이크 결과와 CBOM 기재 알고리즘을
교차 검증하여 tls_verification 정보를 추가합니다.
파이프라인 Step 10에서 호출됩니다.

CycloneDX 1.7 형식에서는 커스텀 데이터가 top-level "properties" 배열에
securecapstone: 네임스페이스로 저장됩니다.

Usage:
  python policy/cbom_diff.py --current <path> --previous <path> --out <path>
  python policy/cbom_diff.py --current <path> --previous <path> --out <path> \\
      --verify-tls --tls-host proxy-server --fail-on-mismatch
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# cbom_gen 의 stage 분류 로직 재사용. 같은 디렉터리에 있다는 가정.
# 분류 규칙 (HYBRID/PURE PQC 패턴) 을 두 모듈에서 따로 들고 있으면 diverge 위험.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cbom_gen import classify_stage  # noqa: E402


# Stage 정책에 따라 클라이언트가 강제할 TLS 1.3 group.
# openssl s_client 는 -groups 옵션 없이 호출되면 OQS provider 가 활성
# 상태여도 클래식 group 을 우선시한다. Stage 시연 시 의도한 group 으로
# 협상되도록 명시적으로 강제할 필요가 있다.
# Stage 1 은 클래식이라 매핑하지 않음 (.get 으로 None 반환되어 기본 동작).
STAGE_TLS_GROUPS = {
    "2": "X25519MLKEM768",                    # Stage 2: 하이브리드 PQC
    "3": "p521_mlkem1024:p384_mlkem768",      # Stage 3: 강한 하이브리드 PQC (NIST L5)
    # NOTE: standalone mlkem1024는 OQS-Nginx 0.11.0 빌드에서 협상 불가하여
    # nginx-pq.conf와 동일하게 hybrid 그룹으로 통일.
}


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def get_property(bom, name):
    """CycloneDX BOM의 top-level properties에서 특정 이름의 값을 꺼낸다."""
    for p in bom.get("properties", []):
        if p.get("name") == name:
            raw = p.get("value", "")
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return raw
    return None


def set_property(bom, name, value):
    """CycloneDX BOM의 top-level properties에 값을 설정(덮어쓰기)한다.

    None 은 property emit 자체를 skip — cbom_gen.make_property 의 prune_none
    동작과 일관성 유지. 과거엔 str(None)='None' 으로 박혀서 get_property 가
    "None" 문자열을 돌려주는 round-trip 비대칭 버그가 있었다.
    """
    if value is None:
        return
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False)
    elif isinstance(value, bool):
        rendered = "true" if value else "false"
    else:
        rendered = str(value)

    props = bom.setdefault("properties", [])

    for p in props:
        if p.get("name") == name:
            p["value"] = rendered
            return

    props.append({"name": name, "value": rendered})


def finding_key(r):
    return f"{r['file']}:{r['line']}:{r['rule']}"


def compare(current_bom, previous_bom):
    """현재·이전 CBOM의 마이그레이션 정보를 비교하여 진척도 dict를 반환."""
    migration_summary = get_property(current_bom, "securecapstone:migration_summary") or {}
    findings = get_property(current_bom, "securecapstone:classical_crypto_findings") or []

    curr_count = 0
    if isinstance(migration_summary, dict):
        curr_count = migration_summary.get("manual_action_required", 0)
    curr_findings = set()
    if isinstance(findings, list):
        curr_findings = {finding_key(r) for r in findings if isinstance(r, dict)}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if previous_bom is None:
        return {
            "compared_at": now,
            "status": "BASELINE",
            "note": "No previous CBOM found — this is the baseline run",
            "current_manual_required": curr_count,
            "delta": 0,
        }

    prev_summary = get_property(previous_bom, "securecapstone:migration_summary") or {}
    prev_findings_list = get_property(previous_bom, "securecapstone:classical_crypto_findings") or []

    prev_count = 0
    if isinstance(prev_summary, dict):
        prev_count = prev_summary.get("manual_action_required", 0)
    prev_findings = set()
    if isinstance(prev_findings_list, list):
        prev_findings = {finding_key(r) for r in prev_findings_list if isinstance(r, dict)}

    resolved = sorted(prev_findings - curr_findings)
    new_findings = sorted(curr_findings - prev_findings)
    delta = prev_count - curr_count

    if delta > 0:
        status = "IMPROVED"
    elif delta < 0:
        status = "REGRESSED"
    else:
        status = "UNCHANGED"

    progress = {
        "compared_at": now,
        "status": status,
        "previous_manual_required": prev_count,
        "current_manual_required": curr_count,
        "delta": delta,
        "resolved_count": len(resolved),
        "new_count": len(new_findings),
    }

    if resolved:
        progress["resolved"] = resolved
    if new_findings:
        progress["new_findings"] = new_findings

    return progress


##############################################################################
# TLS 실제 스택 검증
#
# CBOM에 기재된 알고리즘이 실제 서버의 TLS 핸드셰이크 결과와 일치하는지
# 교차 검증한다.  스키마 검증(CycloneDX validate)이 "형식"을 보장한다면,
# 이 검증은 "내용"의 정확성을 보장한다.
#
# NOTE: 이 검증은 docker-compose 환경(proxy-server 서비스가 존재하는 환경)
#       에서 실행되는 것을 전제로 한다. GitHub Actions 등 외부 CI에서
#       대상 호스트에 접근 불가 시 SKIPPED 처리된다.
#
# TODO: 단위 테스트 추가 (키워드 추출 / 매칭 로직)
# TODO: 서버 지원 전체 cipher suite 열거 (현재는 협상된 1개만 검증)
##############################################################################


def _build_handshake_cmd(host: str, port: int, exec_container: str | None,
                          tls_groups: str | None = None) -> list[str] | None:
    """openssl s_client 명령을 구성한다. exec_container 가 주어지면
    `docker exec <container> openssl ...` 형태로 컨테이너 내부에서 실행하도록
    구성한다 (러너 호스트에서 내부 DNS 해석 불가 + OQS provider 부재 대응).

    tls_groups 가 주어지면 -groups <groups> 옵션을 추가하여 협상 group 을
    강제한다 (Stage 정책 시연용).

    호출 가능한 바이너리가 없으면 None 을 반환한다.
    """
    if exec_container:
        docker = shutil.which("docker")
        if docker is None:
            print("[WARN] docker CLI를 찾을 수 없어 컨테이너 경유 TLS 검증을 건너뜁니다.",
                  file=sys.stderr)
            return None
        # 컨테이너 내부 openssl 사용 (PATH 의존). openquantumsafe/curl 베이스
        # 이미지는 OQS provider 가 번들된 openssl 을 기본 PATH 에 둔다.
        cmd = [docker, "exec", exec_container,
               "openssl", "s_client", "-connect", f"{host}:{port}",
               "-brief", "-no_ign_eof"]
    else:
        openssl = shutil.which("openssl")
        if openssl is None:
            print("[WARN] openssl이 설치되어 있지 않아 TLS 검증을 건너뜁니다.",
                  file=sys.stderr)
            return None
        cmd = [openssl, "s_client", "-connect", f"{host}:{port}",
               "-brief", "-no_ign_eof"]

    if tls_groups:
        cmd.extend(["-groups", tls_groups])

    return cmd


def _parse_handshake_output(output: str) -> dict:
    """openssl s_client -brief 의 stdout+stderr 합본 텍스트를 파싱한다.

    콜론이 없는 라인은 안전하게 무시한다 (IndexError 방지).
    출력 예:
        Protocol version: TLSv1.3
        Ciphersuite: TLS_AES_256_GCM_SHA384
        Peer signing digest: SHA256
        Server Temp Key: X25519, 253 bits
        Server Temp Key: X25519MLKEM768, ...   (OQS provider)
    """
    result: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            # 빈 라인, 진단 메시지, 인증서 페이로드 등 — 안전하게 스킵
            continue
        key, _, val = line.partition(":")
        val = val.strip()
        if key.startswith("Protocol version"):
            result["protocol"] = val
        elif key.startswith("Ciphersuite"):
            result["cipher"] = val
        elif key.startswith("Server Temp Key"):
            # "X25519, 253 bits" or "X25519MLKEM768, ..." 등
            result["group"] = val.split(",")[0].strip()
    return result


def _run_tls_handshake(host: str, port: int,
                      exec_container: str | None = None,
                      tls_groups: str | None = None) -> dict | None:
    """openssl s_client 로 TLS 핸드셰이크를 수행하고 협상 결과를 반환한다.

    openssl s_client 출력은 curl -v 보다 구조적이고 버전 간 포맷이 안정적이다.

    Args:
        host: 핸드셰이크 대상 호스트.
        port: 핸드셰이크 대상 포트.
        exec_container: 지정 시 `docker exec <container> openssl ...` 로 실행.
            러너 호스트에서 docker-compose 내부 서비스명 DNS 해석이 안 되거나
            OQS provider 가 없는 경우 우회 수단으로 사용.
        tls_groups: 지정 시 `-groups <groups>` 로 협상 group 을 강제.
    """
    cmd = _build_handshake_cmd(host, port, exec_container, tls_groups=tls_groups)
    if cmd is None:
        return None

    try:
        r = subprocess.run(
            cmd,
            input="",  # stdin EOF → 즉시 종료
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    # docker exec 자체가 실패한 경우 (컨테이너 부재/정지 등) 출력이 비어있음
    output = (r.stdout or "") + "\n" + (r.stderr or "")
    result = _parse_handshake_output(output)

    if "cipher" not in result:
        # 핸드셰이크 결과를 못 얻은 경우 (연결 실패, openssl 부재, 컨테이너 오류)
        return None

    result.setdefault("protocol", "")
    result.setdefault("group", "")
    return result


def _extract_cbom_algorithms(bom: dict) -> set[str]:
    """CBOM components 에서 algorithm assetType 을 가진 컴포넌트 이름을 수집한다."""
    names: set[str] = set()
    for comp in bom.get("components", []):
        cp = comp.get("cryptoProperties", {})
        if cp.get("assetType") == "algorithm":
            names.add(comp.get("name", ""))
    return names


# BOM 의 pqc_status (cbom_gen 의 classify_stage 결과) → Stage 숫자 매핑.
# 사용자가 --tls-stage 안 박았을 때 BOM 클레임을 default 로 쓰기 위함.
_PQC_STATUS_TO_STAGE = {
    "STAGE_1_CLASSICAL":     "1",
    "STAGE_2_HYBRID_PQC":    "2",
    "STAGE_3_POST_QUANTUM":  "3",
}


def _extract_bom_stage(bom: dict) -> str | None:
    """BOM 의 securecapstone:pqc_status property 에서 Stage 숫자를 추출.

    pqc_status 가 DYNAMIC_ANALYSIS_FAILED / UNKNOWN / 미설정인 경우 None.
    호출자는 None 을 받으면 BOM-driven gating 을 건너뛴다.
    """
    status = get_property(bom, "securecapstone:pqc_status")
    if not isinstance(status, str):
        return None
    return _PQC_STATUS_TO_STAGE.get(status)


# cbom_gen.classify_stage() 의 반환값 (문자열 status) → 숫자 stage 매핑.
# UNKNOWN/DYNAMIC_ANALYSIS_FAILED 는 단정 불가 (0) — 클레임 비교 시 항상 더 낮음.
_NEGOTIATED_STAGE_RANK = {
    "STAGE_1_CLASSICAL":    1,
    "STAGE_2_HYBRID_PQC":   2,
    "STAGE_3_POST_QUANTUM": 3,
}


def _assess_stage_compliance(stage: str, handshake: dict,
                             enforced_groups: str | None = None) -> tuple[bool, str]:
    """Stage 정책 대비 실제 핸드셰이크가 다운그레이드 됐는지 판정.

    Stage 2/3 가 BOM 또는 사용자에 의해 강제되었는데 실제 협상의 negotiated
    group 분류가 클레임보다 낮으면 다운그레이드. 핵심 목적은 "BOM 이 PQC
    라고 클레임했는데 진짜 그 수준의 PQC 가 협상됐는가" 검증이다. OQS provider
    부재/runtime 로드 실패 같은 silent fallback 을 게이트가 잡아야 한다.

    Stage 분류는 cbom_gen.classify_stage() 를 재사용한다 — HYBRID(Stage 2,
    예: X25519MLKEM768) vs PURE/P-curve(Stage 3, 예: p384_mlkem768) 분리.
    "MLKEM 들었는지" 단순 substring 체크는 Stage 3 클레임 + Stage 2 hybrid
    fallback 을 못 잡는다 (regression-tested).

    enforced_groups 가 주어지면(-groups 강제 핸드셰이크), 협상 group 을 읽지
    못해(UNKNOWN) 다운그레이드로 단정하는 false positive 를 막는다. 자세한
    근거는 아래 주석 참조.

    반환: (compliant, reason). reason 은 non-compliant 일 때만 의미 있음.
    """
    if stage not in ("2", "3"):
        # Stage 1 (클래식) 은 다운그레이드 개념 없음. UNKNOWN/None 도 통과.
        return True, ""
    protocol = (handshake.get("protocol") or "").strip()
    group = handshake.get("group") or ""

    # negotiated group 의 실제 stage 분류.
    negotiated_status = classify_stage(group)
    if negotiated_status == "UNKNOWN" and enforced_groups:
        # 협상 group 을 읽지 못함 — 예: tls-tester 의 OpenSSL < 3.2.0 은
        # SSL_get_negotiated_group() 미지원이라 's_client' 출력에 'Server Temp
        # Key' 라인이 없어 group='' 가 된다 (scanner/tls_check.sh 주석 참고).
        # 그러나 -groups 로 강제된 핸드셰이크가 여기까지 도달했다는 것은
        # (verify_tls_against_cbom 은 handshake 실패 시 SKIPPED 로 먼저 반환)
        # 클라가 제시한 그 group 들 중 하나로 협상됐다는 뜻이다 — TLS 는 제시
        # 되지 않은 group 으로 협상할 수 없다. 따라서 '못 읽음'을 다운그레이드로
        # 단정하지 않고, 강제 group 중 가장 낮은 분류를 보수적으로 채택한다.
        forced = [classify_stage(g.strip())
                  for g in enforced_groups.split(":") if g.strip()]
        forced = [s for s in forced if s != "UNKNOWN"]
        if forced:
            negotiated_status = min(
                forced, key=lambda s: _NEGOTIATED_STAGE_RANK.get(s, 0))
            group = f"{enforced_groups} (enforced; group readback 불가)"
    negotiated_rank = _NEGOTIATED_STAGE_RANK.get(negotiated_status, 0)
    claimed_rank = int(stage)

    if negotiated_rank < claimed_rank:
        return False, (
            f"Stage {stage} 클레임인데 negotiated group='{group}' 은 "
            f"{negotiated_status} 로 분류됨 — Stage {negotiated_rank or '?'} "
            f"수준의 협상. silent fallback 가능성.")
    # ML-KEM key_share 는 TLS 1.3 전용이므로 stage 2/3 + TLS 1.2 다운그레이드.
    if protocol and "TLSV1.3" not in protocol.upper().replace(" ", ""):
        return False, (f"Stage {stage} 정책은 TLS 1.3 필수 — "
                       f"negotiated protocol='{protocol}' (다운그레이드)")
    return True, ""


def _normalize(name: str) -> str:
    """비교를 위해 이름을 정규화한다 (소문자, 구분자 제거)."""
    return name.lower().replace("-", "").replace("_", "").replace(" ", "")


def _cipher_to_keywords(cipher: str, group: str) -> list[str]:
    """협상된 cipher suite / key group 문자열에서 비교용 키워드를 추출한다.

    반환값은 CBOM 컴포넌트 이름과 정규화 후 **완전 일치**로 비교된다.
    부분문자열 매칭은 false positive 위험이 있으므로 사용하지 않는다.
    """
    keywords: list[str] = []
    upper = cipher.upper().replace("-", "_")

    if "CHACHA20" in upper and "POLY1305" in upper:
        keywords.append("ChaCha20-Poly1305")
    elif "CHACHA20" in upper:
        keywords.append("ChaCha20")

    aes = re.search(r"AES[_]?(\d{3})[_]?(GCM|CCM|CBC)", upper)
    if aes:
        keywords.append(f"AES-{aes.group(1)}-{aes.group(2)}")

    sha = re.search(r"SHA[_]?(\d{3})", upper)
    if sha:
        keywords.append(f"SHA{sha.group(1)}")

    if "ECDHE" in upper:
        keywords.append("ECDHE")
    if "ECDSA" in upper:
        keywords.append("ECDSA")
    if re.search(r"(^|_)RSA(_|$)", upper):
        keywords.append("RSA")

    # Key group (e.g. X25519, X25519MLKEM768, P256)
    g_upper = group.upper()
    mlkem = re.search(r"MLKEM[_-]?(\d+)", g_upper)
    if mlkem:
        keywords.append(f"ML-KEM-{mlkem.group(1)}")
    if "X25519" in g_upper:
        keywords.append("X25519")
    # cbom_gen.py 는 P-curve 그룹을 ECDH-P-{N} 형태로 정규화한다
    # (TLS_GROUP_ALIASES, decompose_key_exchange_name 참고).
    # 따라서 ECDH-P-{N} 형태도 함께 키워드에 포함시켜 매칭 누락을 방지한다.
    # 기존 호출자 호환을 위해 P-{N} 형태도 유지한다.
    if "P256" in g_upper or "PRIME256" in g_upper or "SECP256R1" in g_upper:
        keywords.extend(["P-256", "ECDH-P-256"])
    if "P384" in g_upper or "SECP384R1" in g_upper:
        keywords.extend(["P-384", "ECDH-P-384"])
    if "P521" in g_upper or "SECP521R1" in g_upper:
        keywords.extend(["P-521", "ECDH-P-521"])

    return keywords


def _match_keyword_in_cbom(keyword: str, cbom_normalized: set[str]) -> bool:
    """정규화 후 완전 일치로 CBOM 알고리즘 목록과 비교한다."""
    return _normalize(keyword) in cbom_normalized


def verify_tls_against_cbom(bom: dict, host: str, port: int,
                             exec_container: str | None = None,
                             tls_stage: str | None = None) -> dict:
    """실제 TLS 핸드셰이크 결과와 CBOM 기재 알고리즘을 교차 검증한다.

    exec_container 가 지정되면 호스트가 아닌 해당 docker 컨테이너 내부에서
    핸드셰이크를 수행한다 (CI 러너에서 docker-compose 내부 DNS / OQS provider
    부재 문제 우회용).

    tls_stage 가 지정되면 STAGE_TLS_GROUPS 매핑에 따라 클라이언트가 협상할
    group 을 강제한다. Stage 2 → X25519MLKEM768, Stage 3 → mlkem1024.
    미지정 시 BOM 의 securecapstone:pqc_status 에서 Stage 를 추론한다.
    이렇게 BOM-driven default 를 적용하지 않으면 사용자가 --tls-stage 를
    빠뜨렸을 때 OQS provider 가 죽어 클래식으로 fallback 된 silent 다운그레이드를
    게이트가 못 잡는다 (false PASS).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result: dict = {"verified_at": now, "host": host, "port": port}
    if exec_container:
        result["exec_container"] = exec_container

    # --tls-stage 우선, 미지정 시 BOM pqc_status 에서 default.
    # CLI 와 BOM 둘 다 있고 서로 다르면 사용자가 명시한 CLI 를 따르되, BOM 의
    # 클레임을 result 에 별도 surface 해서 disagreement 가 silent 하지 않게.
    bom_stage = _extract_bom_stage(bom)
    effective_stage = str(tls_stage) if tls_stage else bom_stage
    stage_source = None
    if tls_stage:
        stage_source = "cli"
    elif effective_stage:
        stage_source = "bom"

    tls_groups = STAGE_TLS_GROUPS.get(effective_stage) if effective_stage else None
    if effective_stage:
        result["stage"] = effective_stage
        result["stage_source"] = stage_source
    if bom_stage and tls_stage and bom_stage != str(tls_stage):
        # CLI override 가 BOM 클레임과 다름 — 운영자가 알 수 있게 표시.
        # CI 로그에서 "왜 stage 3 로 검사했지? BOM 은 stage 2 인데" 같은
        # 의문을 막는다.
        result["bom_stage"] = bom_stage
        result["stage_disagreement"] = (
            f"--tls-stage={tls_stage} 가 BOM pqc_status (stage {bom_stage}) "
            f"와 다름. CLI 값으로 게이팅; BOM 이 stale 일 수 있음.")
    if tls_groups:
        result["enforced_groups"] = tls_groups

    handshake = _run_tls_handshake(host, port, exec_container=exec_container,
                                    tls_groups=tls_groups)
    if handshake is None:
        result["status"] = "SKIPPED"
        via = f" (via {exec_container})" if exec_container else ""
        groups_note = f" [groups={tls_groups}]" if tls_groups else ""
        result["reason"] = (f"TLS 핸드셰이크 실패 — {host}:{port}{via}"
                            f"{groups_note} 에 연결할 수 없음")
        return result

    result["negotiated"] = handshake
    cbom_algos = _extract_cbom_algorithms(bom)
    # 정규화된 이름 집합 — 완전 일치 비교에 사용
    cbom_normalized = {_normalize(a) for a in cbom_algos}

    keywords = _cipher_to_keywords(handshake["cipher"], handshake["group"])
    matched: list[str] = []
    missing: list[str] = []

    for kw in keywords:
        if _match_keyword_in_cbom(kw, cbom_normalized):
            matched.append(kw)
        else:
            missing.append(kw)

    result["matched"] = matched
    result["missing_in_cbom"] = missing
    result["cbom_algorithm_count"] = len(cbom_algos)

    # Stage 정책 위반 (다운그레이드) 우선 판정 — keyword 누락보다 먼저.
    # 이유: BOM 이 Stage 2 PQC 라고 클레임했는데 실제 협상이 클래식이면,
    # 클래식 group 이름(예: X25519) 이 BOM 컴포넌트 목록에 있어 keyword
    # superset 체크는 통과한다 — 그러나 정책 게이트는 실패해야 한다.
    if effective_stage:
        compliant, reason = _assess_stage_compliance(
            effective_stage, handshake, enforced_groups=tls_groups)
        if not compliant:
            result["status"] = "DOWNGRADE_DETECTED"
            result["detail"] = reason
            return result

    if not missing:
        result["status"] = "PASS"
        result["detail"] = "협상된 모든 알고리즘이 CBOM에 기재되어 있음"
    else:
        result["status"] = "MISMATCH"
        result["detail"] = "CBOM에 누락된 알고리즘 발견"
    return result


def print_tls_verification(v: dict):
    print("\n=== TLS ↔ CBOM 교차 검증 ===")
    status = v.get("status", "UNKNOWN")

    if status == "SKIPPED":
        print(f"[SKIP] {v.get('reason', 'TLS 연결 불가')}")
        return

    neg = v.get("negotiated", {})
    print(f"  서버       : {v['host']}:{v['port']}")
    print(f"  Protocol   : {neg.get('protocol', '?')}")
    print(f"  Cipher     : {neg.get('cipher', '?')}")
    print(f"  Key Group  : {neg.get('group', '?')}")
    if v.get("stage"):
        src = v.get("stage_source", "?")
        print(f"  Stage 정책 : {v['stage']} (source: {src})")
    if v.get("stage_disagreement"):
        print(f"  [WARN] {v['stage_disagreement']}")
    print(f"  CBOM 알고리즘: {v['cbom_algorithm_count']}개")

    if status == "PASS":
        print(f"[PASS] 협상 알고리즘 전부 CBOM 내 확인 — {v['matched']}")
    elif status == "DOWNGRADE_DETECTED":
        print(f"[DOWNGRADE] {v.get('detail', '다운그레이드 감지')}")
        if v.get("matched"):
            print(f"  일치 항목: {v['matched']}")
    else:
        print(f"[MISMATCH] CBOM 누락: {v['missing_in_cbom']}")
        if v.get("matched"):
            print(f"  일치 항목: {v['matched']}")


def print_summary(progress):
    print("=== CBOM Migration Progress ===")
    status = progress["status"]

    if status == "BASELINE":
        print(f"[BASELINE] 첫 번째 실행 — 기준선 설정")
        print(f"  수동 조치 필요: {progress['current_manual_required']}건")
    else:
        prev = progress["previous_manual_required"]
        curr = progress["current_manual_required"]
        delta = progress["delta"]

        print(f"  이전: {prev}건 → 현재: {curr}건")

        resolved_count = progress.get("resolved_count", 0)
        new_count = progress.get("new_count", 0)

        if status == "IMPROVED":
            print(f"[IMPROVED] 해결 {resolved_count}건 / 신규 {new_count}건 (전체 {delta}건 감소)")
        elif status == "REGRESSED":
            print(f"[REGRESSED] 해결 {resolved_count}건 / 신규 {new_count}건 (전체 {abs(delta)}건 증가)")
        else:
            print(f"[UNCHANGED] 해결 {resolved_count}건 / 신규 {new_count}건 (변화 없음)")

        if progress.get("resolved"):
            print(f"  해결된 항목 ({progress['resolved_count']}건):")
            for r in progress["resolved"]:
                print(f"    - {r}")
        if progress.get("new_findings"):
            print(f"  신규 발견 ({progress['new_count']}건):")
            for r in progress["new_findings"]:
                print(f"    - {r}")


def main():
    parser = argparse.ArgumentParser(description="CycloneDX CBOM 마이그레이션 이력 비교 및 TLS 스택 검증")
    parser.add_argument("--current", required=True, help="현재 CBOM JSON 경로")
    parser.add_argument("--previous", required=True, help="이전 CBOM JSON 경로 (없으면 BASELINE)")
    parser.add_argument("--out", required=True, help="출력 CBOM JSON 경로")
    parser.add_argument("--verify-tls", action="store_true",
                        help="실제 TLS 핸드셰이크와 CBOM 알고리즘 교차 검증")
    parser.add_argument("--tls-host", default="proxy-server",
                        help="TLS 검증 대상 호스트 (default: proxy-server)")
    parser.add_argument("--tls-port", type=int, default=443,
                        help="TLS 검증 대상 포트 (default: 443)")
    parser.add_argument("--tls-exec-container", default=None,
                        help="지정 시 호스트가 아닌 해당 docker 컨테이너 내부에서 "
                             "openssl s_client 를 실행한다. CI 러너에서 "
                             "docker-compose 내부 서비스명 DNS 해석 불가 + "
                             "OQS provider 부재 문제 우회용 "
                             "(예: --tls-exec-container tls-tester).")
    parser.add_argument("--tls-stage", default=None,
                        choices=["1", "2", "3"],
                        help="지정 시 Stage 정책에 맞춰 openssl s_client 의 "
                             "-groups 옵션을 자동 부여한다. "
                             "Stage 2: X25519MLKEM768, Stage 3: mlkem1024 강제. "
                             "지정 없으면 OpenSSL 기본 group 순서를 사용 "
                             "(클래식 우선이라 PQC 환경에서도 클래식으로 "
                             "fallback 될 수 있음).")
    parser.add_argument("--fail-on-mismatch", action="store_true",
                        help="TLS ↔ CBOM 불일치(MISMATCH) 또는 Stage 정책 "
                             "다운그레이드(DOWNGRADE_DETECTED) 시 exit 1. "
                             "다운그레이드는 BOM 이 Stage 2/3 PQC 를 클레임했는데 "
                             "실제 핸드셰이크가 클래식/TLS 1.2 로 떨어지는 경우.")
    parser.add_argument("--fail-on-skip", action="store_true",
                        help="TLS 검증 SKIPPED(openssl 미설치/연결 불가) 시에도 exit 1")
    args = parser.parse_args()

    current = load_json(args.current)
    if current is None:
        print(f"[ERROR] 현재 CBOM 파일을 읽을 수 없습니다: {args.current}", file=sys.stderr)
        sys.exit(1)

    previous = load_json(args.previous)

    progress = compare(current, previous)

    # CycloneDX properties에 migration_progress 추가
    set_property(current, "securecapstone:migration_progress", progress)

    # TLS ↔ CBOM 교차 검증
    tls_result = None
    if args.verify_tls:
        tls_result = verify_tls_against_cbom(
            current, args.tls_host, args.tls_port,
            exec_container=args.tls_exec_container,
            tls_stage=args.tls_stage,
        )
        set_property(current, "securecapstone:tls_verification", tls_result)

    with open(args.out, "w") as f:
        json.dump(current, f, indent=2, ensure_ascii=False)

    print_summary(progress)

    exit_code = 0
    if tls_result:
        print_tls_verification(tls_result)
        status = tls_result.get("status")
        if args.fail_on_mismatch and status == "MISMATCH":
            print("[FATAL] --fail-on-mismatch: CBOM과 실제 TLS 스택 불일치",
                  file=sys.stderr)
            exit_code = 1
        elif args.fail_on_mismatch and status == "DOWNGRADE_DETECTED":
            print("[FATAL] --fail-on-mismatch: Stage 정책 다운그레이드 — "
                  f"{tls_result.get('detail', '')}",
                  file=sys.stderr)
            exit_code = 1
        elif args.fail_on_skip and status == "SKIPPED":
            print("[FATAL] --fail-on-skip: TLS 검증을 수행할 수 없음",
                  file=sys.stderr)
            exit_code = 1

    print(f"[DONE] securecapstone:migration_progress 속성 추가 완료 → {args.out}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
