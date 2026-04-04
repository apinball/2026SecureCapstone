"""
TLS Termination CBOM Generator
================================
nginx TLS 설정(정적 분석) + 실제 핸드셰이크/인증서 정보(동적 분석)를 결합해
TLS Termination 범위의 암호 자산을 JSON으로 기록한다.

repo 기준 (feature/pqc-webserver-fix 브랜치):
- nginx stage 설정 파일: nginx/nginx-ecc.conf, nginx/nginx-hybrid.conf, nginx/nginx-pq.conf
- tester 컨테이너: tls-tester  (curl 기반 verify_tls.sh)
- server 컨테이너: pqc-proxy
- 기본 검증 호스트: proxy-server
- verify_tls.sh 실행 방식: docker exec tls-tester verify_tls.sh proxy-server 443 <stage>

CI 파이프라인 연동 (devsecops-pipeline.yml Step 6):
  python policy/cbom_gen.py --stage $STAGE --out artifacts/cbom_stage${STAGE}.json

로컬 실행 예시:
  python policy/cbom_gen.py --stage 2 --out artifacts/cbom_stage2.json
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── 단계별 nginx 설정 파일 매핑 ──────────────────────────────────────────────
STAGE_CONFIG_MAP = {
    "1": "nginx/nginx-ecc.conf",
    "2": "nginx/nginx-hybrid.conf",
    "3": "nginx/nginx-pq.conf",
    "auto": "nginx/nginx.conf",
}


# ── 환경변수 기본값 (.env 있으면 자동 반영) ──────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DEFAULT_HOST = os.getenv("PROXY_HOST", "proxy-server")
DEFAULT_PORT = int(os.getenv("PROXY_PORT", "443"))
DEFAULT_TESTER = os.getenv("TESTER_CONTAINER", "tls-tester")
DEFAULT_SERVER = os.getenv("SERVER_CONTAINER", "pqc-proxy")
DEFAULT_CERT_PATH = os.getenv("SERVER_CERT_PATH", "/etc/nginx/certs/server.crt")
DEFAULT_VERIFY_SCRIPT = os.getenv("VERIFY_SCRIPT", "tls_check.sh")
DEFAULT_STRICT_VALIDATION = os.getenv("STRICT_VALIDATION", "false").strip().lower() in {
    "1", "true", "yes", "on"
}


# ── PQC 알고리즘 패턴 (명시적 매칭) ──────────────────────────────────────────
# Stage 2: X25519 + MLKEM 하이브리드 — [_\s]* 로 구분자 유무 모두 커버
HYBRID_PQC_PATTERNS = [
    re.compile(r"x25519[_\s]*mlkem", re.IGNORECASE),
]
# Stage 3: P-curve + MLKEM 또는 순수 PQC
# 두 번째 패턴은 negative lookbehind로 하이브리드 문자열 내 오매칭을 방지
PURE_PQC_PATTERNS = [
    re.compile(r"p\d+[_\s]*mlkem", re.IGNORECASE),
    re.compile(r"(?<![a-zA-Z\d])mlkem\d+", re.IGNORECASE),
]


# ── TLS directive 파싱 패턴 (정적/컨테이너 분석 공용) ─────────────────────────
TLS_DIRECTIVE_PATTERNS = {
    "ssl_protocols": (r"ssl_protocols\s+([^;]+);", "space"),
    "ssl_ciphers": (r"ssl_ciphers\s+([^;]+);", "colon_or_space"),
    "ssl_ecdh_curve": (r"ssl_ecdh_curve\s+([^;]+);", "colon_or_space"),
    "ssl_certificate": (r"ssl_certificate\s+([^;]+);", "raw"),
    "ssl_certificate_key": (r"ssl_certificate_key\s+([^;]+);", "raw"),
}


# ── 유틸 ──────────────────────────────────────────────────────────────────────
def normalize_stage(stage: str) -> str:
    """stage 인자를 정규화된 숫자 문자열로 변환.

    CI 환경에서는 $GITHUB_ENV를 통해 STAGE 환경변수가 설정되므로,
    --stage auto일 때 이를 자동으로 감지한다.
    """
    value = (stage or "auto").strip().lower()

    aliases = {
        "1": "1", "ecc": "1",
        "2": "2", "hybrid": "2",
        "3": "3", "pq": "3",
        "auto": "auto",
    }
    result = aliases.get(value)

    if result is None:
        print(
            f"[WARN] 알 수 없는 stage 값 '{stage}' → auto로 대체합니다. "
            f"유효 값: {', '.join(sorted(aliases.keys()))}",
            file=sys.stderr,
        )
        result = "auto"

    # auto인 경우 CI 환경변수 $STAGE에서 자동 감지 시도
    if result == "auto":
        ci_stage = os.getenv("STAGE", "").strip()
        if ci_stage in ("1", "2", "3"):
            result = ci_stage

    return result


def run_cmd(cmd: list, timeout: int = 30) -> dict:
    """외부 명령어를 실행하고 결과를 dict로 반환."""
    rendered_cmd = " ".join(shlex.quote(x) for x in cmd)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            encoding='utf-8',
            timeout=timeout,
        )
        return {
            "cmd": rendered_cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
        }

    except subprocess.TimeoutExpired as e:
        return {
            "cmd": rendered_cmd,
            "returncode": 124,
            "stdout": (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
            "stderr": (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
            "error": "timeout",
        }

    except FileNotFoundError:
        return {
            "cmd": rendered_cmd,
            "returncode": 127,
            "stdout": "",
            "stderr": "",
            "error": "command_not_found",
        }


def resolve_config_path(stage: str, config_path: str) -> str:
    """stage 기반으로 nginx 설정 파일 경로를 결정."""
    if config_path:
        return config_path
    return STAGE_CONFIG_MAP.get(stage, "nginx/nginx.conf")


def split_directive_value(raw: str, mode: str) -> list:
    """nginx 디렉티브 값을 파싱하여 리스트로 분리."""
    if mode == "colon_or_space":
        return [x.strip() for x in re.split(r"[:\s]+", raw) if x.strip()]
    if mode == "space":
        return [x.strip() for x in raw.split() if x.strip()]
    return [raw.strip()]


def _parse_directives(config_text: str, patterns: dict) -> dict:
    """설정 텍스트에서 정규식 패턴 딕셔너리에 해당하는 디렉티브를 추출하는 내부 헬퍼."""
    findings = {}
    for key, (pattern, mode) in patterns.items():
        m = re.search(pattern, config_text, re.MULTILINE)
        if not m:
            continue
        raw = m.group(1).strip()
        if mode == "raw":
            findings[key] = raw
        else:
            findings[key] = split_directive_value(raw, mode)
    return findings


# ── 정적 분석 ────────────────────────────────────────────────────────────────
def static_analysis(config_path: str) -> dict:
    """로컬 nginx 설정 파일을 파싱하여 TLS 관련 디렉티브를 추출."""
    result = {
        "method": "static",
        "source": config_path,
        "findings": {},
        "notes": [],
    }

    try:
        text = Path(config_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        result["error"] = f"{config_path} 파일 없음"
        return result
    except OSError as e:
        result["error"] = f"{config_path} 읽기 실패: {e}"
        return result

    result["findings"] = _parse_directives(text, TLS_DIRECTIVE_PATTERNS)

    # TLS 1.3 전용 설정에서 ssl_ciphers가 없는 건 정상
    protocols = result["findings"].get("ssl_protocols", [])
    if "ssl_ciphers" not in result["findings"]:
        if protocols == ["TLSv1.3"]:
            result["notes"].append(
                "TLS 1.3 전용 설정으로 ssl_ciphers 미지정 (정상). "
                "TLS 1.3 cipher suite는 OpenSSL이 자동 협상합니다. "
                "(TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 등)"
            )
        else:
            result["notes"].append(
                "ssl_ciphers가 명시되지 않았습니다. "
                "TLS 1.2 이하 프로토콜이 포함된 경우 기본 cipher에 의존하게 되므로 주의가 필요합니다."
            )

    if not result["notes"]:
        del result["notes"]

    return result


# ── 컨테이너 내 설정 읽기 (보조) ──────────────────────────────────────────────
def read_container_config(
    server_container: str,
    config_path: str = "/opt/nginx/nginx-conf/nginx.conf",
) -> dict:
    """서버 컨테이너 내부에서 실행 중인 실제 nginx.conf를 읽어온다.

    CI에서 nginx.conf가 cp로 교체되므로 로컬 파일과 실제 실행 설정이 다를 수 있다.
    """
    cmd = ["docker", "exec", server_container, "cat", config_path]
    result = run_cmd(cmd, timeout=10)

    if result.get("error") or result["returncode"] != 0:
        err = (result.get("stderr") or result.get("stdout") or "").strip()
        return {"error": f"컨테이너 설정 읽기 실패: {err}"}

    return {"config_text": result["stdout"]}


def parse_nginx_directives(config_text: str) -> dict:
    """컨테이너 내부 nginx 설정 문자열에서 핵심 TLS directive를 추출."""
    return _parse_directives(config_text, TLS_DIRECTIVE_PATTERNS)


# ── 단계 판정 ────────────────────────────────────────────────────────────────
def classify_stage(key_group: str) -> str:
    """협상된 키 교환 그룹을 기반으로 PQC 단계를 판정.

    판정 우선순위:
    1. X25519 + MLKEM -> STAGE_2_HYBRID_PQC  (예: X25519MLKEM768)
    2. P-curve + MLKEM 또는 순수 MLKEM -> STAGE_3_POST_QUANTUM  (예: p521_mlkem1024)
    3. 그 외 값 있음 -> STAGE_1_CLASSICAL
    4. 값 없음 -> UNKNOWN
    """
    g = (key_group or "").strip()
    if not g:
        return "UNKNOWN"

    # Stage 2 먼저 체크 (X25519 + MLKEM 조합)
    for pattern in HYBRID_PQC_PATTERNS:
        if pattern.search(g):
            return "STAGE_2_HYBRID_PQC"

    # Stage 3 체크 (P-curve + MLKEM, 또는 순수 MLKEM)
    for pattern in PURE_PQC_PATTERNS:
        if pattern.search(g):
            return "STAGE_3_POST_QUANTUM"

    return "STAGE_1_CLASSICAL"


# ── verify_tls.sh 출력 파싱 ──────────────────────────────────────────────────
def parse_verify_tls_output(output: str) -> dict:
    """verify_tls.sh의 출력을 파싱.

    tester/verify_tls.sh (curl 기반) 출력 형식:
        Protocol : TLSv1.3
        Cipher   : TLS_AES_256_GCM_SHA384
        Key Group: X25519MLKEM768
        판정: Stage 2 - Hybrid PQC-TLS

    pqc-webserver/scripts/verify_tls.sh (openssl s_client 기반) 출력 형식:
        Protocol version: TLSv1.3
        Ciphersuite: TLS_AES_256_GCM_SHA384
        Negotiated TLS1.3 group: X25519MLKEM768
        판정: Stage 2 - Hybrid PQC-TLS

    주의: Stage 3에서는 "판정:" 라인이 2개 출력되므로 (PQC 연결 확인 + 최종 판정)
    마지막 매칭을 사용한다.
    """
    result = {}

    # 두 가지 스크립트 형식을 모두 커버하는 패턴 (우선순위 순)
    # "판정"을 제외한 패턴은 first-match 사용
    first_match_patterns = [
        # --- 프로토콜 ---
        (r"Protocol\s*(?:version)?\s*:\s*(.+)", "negotiated_protocol"),
        # --- 암호 스위트 ---
        (r"Cipher(?:suite)?\s*:\s*(.+)", "negotiated_cipher"),
        # --- 키 교환 그룹 ---
        (r"Key Group\s*:\s*(.+)", "key_exchange_actual"),
        (r"^Group\s*:\s*(.+)", "key_exchange_actual"),
        (r"Negotiated TLS[\d.]+ group\s*:\s*(.+)", "key_exchange_actual"),
        (r"Server Temp Key\s*:\s*(.+)", "key_exchange_actual"),
        (r"Peer Temp Key\s*:\s*(.+)", "key_exchange_actual"),
    ]

    for pattern, key in first_match_patterns:
        m = re.search(pattern, output, re.IGNORECASE)
        if m and key not in result:
            val = m.group(1).strip()
            if val.lower() != "unknown":
                result[key] = val

    # "판정:" 패턴은 마지막 매칭을 사용 (Stage 3에서 최종 판정 라인 캡처)
    judgement_matches = re.findall(r"판정\s*:\s*(.+)", output)
    if judgement_matches:
        final_judgement = judgement_matches[-1].strip()
        if final_judgement.lower() != "unknown":
            result["verify_tls_judgement"] = final_judgement

    # tls_check.sh 형식: "[PASS] Stage 2 policy satisfied." / "[FAIL] ..."
    if "verify_tls_judgement" not in result:
        if re.search(r"\[PASS\].*Stage\s*(\d+)", output):
            m = re.search(r"\[PASS\].*Stage\s*(\d+)", output)
            result["verify_tls_judgement"] = f"Stage {m.group(1)} - policy satisfied"
        elif re.search(r"\[FAIL\]", output):
            result["verify_tls_judgement"] = "fail"

    return result


# ── 인증서 정보 파싱 ──────────────────────────────────────────────────────────
PQC_CERT_ALGORITHMS = [
    "dilithium", "ml-dsa", "mldsa",
    "falcon", "sphincs", "slh-dsa", "slhdsa",
]


def parse_cert_info(cert_text: str) -> dict:
    """openssl x509 -text 출력에서 인증서 정보를 추출."""
    result = {}

    for pattern, key in [
        (r"subject\s*=\s*([^\n]+)", "subject"),
        (r"issuer\s*=\s*([^\n]+)", "issuer"),
        (r"serial\s*=\s*([^\n]+)", "serial"),
        (r"notBefore\s*=\s*([^\n]+)", "not_before"),
        (r"notAfter\s*=\s*([^\n]+)", "not_after"),
    ]:
        m = re.search(pattern, cert_text)
        if m:
            result[key] = m.group(1).strip()

    m = re.search(r"Signature Algorithm:\s*([^\n]+)", cert_text)
    if m:
        result["cert_signature_algorithm"] = m.group(1).strip()

    m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", cert_text)
    if m:
        result["public_key_bits"] = int(m.group(1))

    m = re.search(r"Public Key Algorithm:\s*([^\n]+)", cert_text)
    if m:
        result["public_key_algorithm"] = m.group(1).strip()

    # 인증서가 PQC 알고리즘인지 판정
    sig_alg = result.get("cert_signature_algorithm", "").lower()
    pk_alg = result.get("public_key_algorithm", "").lower()
    combined_alg = f"{sig_alg} {pk_alg}"

    is_pqc_cert = any(pqc in combined_alg for pqc in PQC_CERT_ALGORITHMS)
    result["is_pqc_certificate"] = is_pqc_cert

    if not is_pqc_cert:
        result["cert_pqc_note"] = (
            "인증서 서명/공개키가 전통적 알고리즘(RSA/ECDSA)입니다. "
            "TLS 키 교환이 PQC라도 인증서 자체는 양자 내성이 아닙니다."
        )

    return result


# ── 교차 검증 ────────────────────────────────────────────────────────────────
def cross_validate(our_status: str, script_judgement: str, requested_stage: str) -> dict:
    """cbom_gen의 classify_stage() 결과와 verify_tls.sh의 판정을 교차 검증."""
    validation = {"consistent": True, "warnings": []}

    if not script_judgement:
        validation["warnings"].append("verify_tls.sh 판정 결과를 파싱하지 못했습니다.")
        return validation

    jl = script_judgement.lower()

    # verify_tls.sh 판정 -> stage 숫자
    # Stage 3 최종 판정 형식: "Stage 3 - PQC 강제 적용 ✓ ..."
    # Stage 2 판정 형식:      "Stage 2 - Hybrid PQC-TLS ✓"
    # Stage 1 판정 형식:      "Stage 1 - Classical TLS (ECC) ..."
    # PQC 키워드 기반 fallback: "pqc" 포함 시 Stage 3로 추정
    if "stage 3" in jl:
        script_stage = "3"
    elif "stage 2" in jl:
        script_stage = "2"
    elif "stage 1" in jl:
        script_stage = "1"
    elif "pqc" in jl and "hybrid" not in jl:
        # fallback: "PQC 강제 적용" 등 stage 번호 없이 PQC만 언급된 경우
        script_stage = "3"
    else:
        script_stage = None

    # cbom_gen classify_stage 결과 -> stage 숫자
    our_stage_map = {
        "STAGE_1_CLASSICAL": "1",
        "STAGE_2_HYBRID_PQC": "2",
        "STAGE_3_POST_QUANTUM": "3",
    }
    our_stage = our_stage_map.get(our_status)

    # 두 판정이 불일치하는 경우
    if script_stage and our_stage and script_stage != our_stage:
        validation["consistent"] = False
        validation["warnings"].append(
            f"판정 불일치: verify_tls.sh는 Stage {script_stage}, "
            f"cbom_gen은 {our_status}으로 판정했습니다. "
            "파싱 로직 또는 알고리즘 매핑을 확인하세요."
        )

    # 요청한 stage와 실제 협상 결과가 다른 경우 — 서버 설정 미적용 가능성
    if requested_stage in ("1", "2", "3") and our_stage and requested_stage != our_stage:
        validation["consistent"] = False
        validation["warnings"].append(
            f"요청 Stage({requested_stage})와 실제 협상 결과(Stage {our_stage})가 다릅니다. "
            "서버 설정이 올바르게 적용되었는지 확인하세요."
        )

    if not validation["warnings"]:
        del validation["warnings"]

    return validation


# ── 동적 분석 ────────────────────────────────────────────────────────────────
def dynamic_analysis(
    host: str,
    port: int,
    tester_container: str,
    server_container: str,
    server_cert_path: str,
    stage: str,
    verify_script: str,
) -> dict:
    """docker exec으로 TLS 핸드셰이크 검증 및 인증서 정보를 수집."""
    result = {
        "method": "dynamic",
        "target": f"{host}:{port}",
        "tester": tester_container,
        "server": server_container,
        "findings": {},
    }

    # ── verify_tls.sh 실행 ──
    verify_cmd = [
        "docker", "exec", tester_container,
        verify_script,
        host, str(port), stage,
    ]
    verify = run_cmd(verify_cmd, timeout=30)
    result["verify_command"] = verify["cmd"]

    if verify.get("error") == "command_not_found":
        result["error"] = "docker 또는 verify_tls.sh 명령어를 찾을 수 없습니다"
        result["findings"]["raw_output"] = verify["stdout"] + verify["stderr"]
        return result

    combined_output = verify["stdout"]
    if verify["stdout"] and verify["stderr"]:
        combined_output += "\n"
    combined_output += verify["stderr"]
    result["findings"]["raw_output"] = combined_output

    if verify.get("error") == "timeout":
        result["error"] = "TLS 검증 타임아웃 (30초 초과)"
    elif verify["returncode"] != 0:
        result["error"] = f"TLS 검증 실패 (exit code: {verify['returncode']})"

    # exit code와 무관하게 가능한 정보는 최대한 파싱
    parsed = parse_verify_tls_output(combined_output)
    result["findings"].update(parsed)

    # 파싱에 성공한 경우 치명 오류 대신 warning 성격으로 완화
    if result.get("error") and result["findings"].get("negotiated_protocol"):
        result["warning"] = result.pop("error")

    # ── 인증서 정보 수집 ──
    # verify_tls.sh가 non-zero여도 서버 컨테이너에서 cert 정보는 여전히 수집 가능하므로 계속 진행.
    cert_cmd = [
        "docker", "exec", server_container,
        "openssl", "x509",
        "-in", server_cert_path,
        "-noout", "-subject", "-issuer", "-serial", "-dates", "-text",
    ]
    cert = run_cmd(cert_cmd, timeout=15)
    result["cert_command"] = cert["cmd"]

    if cert.get("error") == "command_not_found":
        result["cert_error"] = "docker 또는 openssl 명령어를 찾을 수 없습니다"
    elif cert.get("error") == "timeout":
        result["cert_error"] = "인증서 정보 조회 타임아웃"
    elif cert["returncode"] == 0:
        cert_text = cert["stdout"]
        if cert["stdout"] and cert["stderr"]:
            cert_text += "\n"
        cert_text += cert["stderr"]
        result["findings"]["certificate"] = parse_cert_info(cert_text)
    else:
        result["cert_error"] = (cert["stderr"] or cert["stdout"]).strip()

    return result


# ── CBOM 생성 ─────────────────────────────────────────────────────────────────
def generate_cbom(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    stage: str = "auto",
    config_path: str = "",
    tester_container: str = DEFAULT_TESTER,
    server_container: str = DEFAULT_SERVER,
    server_cert_path: str = DEFAULT_CERT_PATH,
    verify_script: str = DEFAULT_VERIFY_SCRIPT,
) -> dict:
    """정적 분석 + 동적 분석 결과를 결합하여 CBOM JSON을 생성."""

    normalized_stage = normalize_stage(stage)
    resolved_config = resolve_config_path(normalized_stage, config_path)

    # ── 정적 분석 (로컬 nginx 설정 파일) ──
    static = static_analysis(resolved_config)

    # ── 컨테이너 실행 설정 보조 확인 ──
    # CI에서 cp로 nginx.conf가 교체되므로 로컬 파일과 컨테이너 내부 설정이 다를 수 있음
    container_conf = read_container_config(server_container)

    # 컨테이너 설정 파싱 결과 캐시 (중복 호출 방지)
    container_findings = None
    if "config_text" in container_conf:
        static["container_config_available"] = True
        container_findings = parse_nginx_directives(container_conf["config_text"])
        local_findings = static.get("findings", {})
        for key in ("ssl_protocols", "ssl_ciphers", "ssl_ecdh_curve", "ssl_certificate", "ssl_certificate_key"):
            local_val = local_findings.get(key)
            container_val = container_findings.get(key)
            if local_val is not None and container_val is not None and local_val != container_val:
                static.setdefault("notes", []).append(
                    f"로컬 설정의 {key}({local_val})와 컨테이너 내부 설정({container_val})이 다릅니다. "
                    "CI에서 nginx.conf가 교체되었을 수 있습니다."
                )
    else:
        static["container_config_available"] = False

    # ── 동적 분석 (TLS 핸드셰이크 + 인증서) ──
    dynamic = dynamic_analysis(
        host=host,
        port=port,
        tester_container=tester_container,
        server_container=server_container,
        server_cert_path=server_cert_path,
        stage=normalized_stage,
        verify_script=verify_script,
    )

    static_f = static.get("findings", {})
    dynamic_f = dynamic.get("findings", {})
    cert_f = dynamic_f.get("certificate", {})

    # effective_static: 컨테이너 설정이 있으면 우선 적용
    effective_static = dict(static_f)
    if container_findings is not None:
        static["effective_findings"] = container_findings
        static["effective_source"] = f"container:{server_container}:/opt/nginx/nginx-conf/nginx.conf"
        for key in ("ssl_protocols", "ssl_ciphers", "ssl_ecdh_curve", "ssl_certificate", "ssl_certificate_key"):
            if container_findings.get(key) is not None:
                effective_static[key] = container_findings[key]
    else:
        static["effective_findings"] = static_f
        static["effective_source"] = resolved_config

    # ── PQC 상태 판정 ──
    key_exchange = dynamic_f.get("key_exchange_actual", "")
    if dynamic.get("error") and not dynamic_f.get("negotiated_protocol"):
        pqc_status = "DYNAMIC_ANALYSIS_FAILED"
    else:
        pqc_status = classify_stage(key_exchange)

    # ── 교차 검증 ──
    validation = cross_validate(
        our_status=pqc_status,
        script_judgement=dynamic_f.get("verify_tls_judgement", ""),
        requested_stage=normalized_stage,
    )

    # ── CBOM 조립 ──
    cbom = {
        "cbom_version": "1.1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generator": "cbom_gen.py",
        "target": {
            "host": host,
            "port": port,
            "stage_requested": normalized_stage,
            "scope": "TLS Termination",
        },
        "pqc_status": pqc_status,
        "validation": validation,
        "crypto_assets": {
            "configured_protocols": effective_static.get("ssl_protocols", []),
            "configured_ciphers": effective_static.get("ssl_ciphers", static_f.get("ssl_ciphers", [])),
            "configured_key_exchange": effective_static.get("ssl_ecdh_curve", []),
            "certificate_path": effective_static.get("ssl_certificate"),
            "private_key_path": effective_static.get("ssl_certificate_key"),
            "config_evidence_source": static.get("effective_source"),
            "negotiated_protocol": dynamic_f.get("negotiated_protocol"),
            "negotiated_cipher": dynamic_f.get("negotiated_cipher"),
            "negotiated_key_exchange": dynamic_f.get("key_exchange_actual"),
            "cert_signature_algorithm": cert_f.get("cert_signature_algorithm"),
            "cert_public_key_algorithm": cert_f.get("public_key_algorithm"),
            "cert_public_key_bits": cert_f.get("public_key_bits"),
            "cert_is_pqc": cert_f.get("is_pqc_certificate"),
            "certificate_subject": cert_f.get("subject"),
            "certificate_issuer": cert_f.get("issuer"),
            "certificate_serial": cert_f.get("serial"),
            "certificate_not_before": cert_f.get("not_before"),
            "certificate_not_after": cert_f.get("not_after"),
        },
        "analysis_detail": {
            "static": static,
            "dynamic": dynamic,
        },
    }

    # None 값 필터링
    cbom["crypto_assets"] = {
        k: v for k, v in cbom["crypto_assets"].items() if v is not None
    }

    return cbom


# ── CLI ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="TLS Termination CBOM Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # Stage 2 검증 후 CBOM 생성
  python policy/cbom_gen.py --stage 2 --out artifacts/cbom_stage2.json

  # CI 파이프라인에서 (STAGE 환경변수 자동 감지)
  python policy/cbom_gen.py --out artifacts/cbom.json

  # 특정 nginx 설정 파일 지정
  python policy/cbom_gen.py --stage 3 --config nginx/nginx-pq.conf
        """,
    )
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"검증 대상 호스트 (기본: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"검증 대상 포트 (기본: {DEFAULT_PORT})")
    parser.add_argument("--stage", default="auto",
                        help="auto | 1 | ecc | 2 | hybrid | 3 | pq (auto시 $STAGE 환경변수 자동 감지)")
    parser.add_argument("--config", default="",
                        help="nginx 설정 파일 경로 (미지정 시 stage에서 자동 선택)")
    parser.add_argument("--tester-container", default=DEFAULT_TESTER,
                        help=f"tester 컨테이너명 (기본: {DEFAULT_TESTER})")
    parser.add_argument("--server-container", default=DEFAULT_SERVER,
                        help=f"server 컨테이너명 (기본: {DEFAULT_SERVER})")
    parser.add_argument("--server-cert-path", default=DEFAULT_CERT_PATH,
                        help=f"서버 인증서 경로 (기본: {DEFAULT_CERT_PATH})")
    parser.add_argument("--verify-script", default=DEFAULT_VERIFY_SCRIPT,
                        help=f"검증 스크립트 (기본: {DEFAULT_VERIFY_SCRIPT})")
    parser.add_argument("--out", default="",
                        help="결과 저장 경로 (미지정 시 stdout만 출력)")
    parser.add_argument(
        "--strict-validation",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_STRICT_VALIDATION,
        help="verify_tls.sh 판정과 cbom_gen 판정이 불일치하면 exit 3으로 종료",
    )
    args = parser.parse_args()

    cbom = generate_cbom(
        host=args.host,
        port=args.port,
        stage=args.stage,
        config_path=args.config,
        tester_container=args.tester_container,
        server_container=args.server_container,
        server_cert_path=args.server_cert_path,
        verify_script=args.verify_script,
    )

    text = json.dumps(cbom, indent=2, ensure_ascii=False)
    print(text)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
        print(f"\nCBOM 저장 완료: {out_path}", file=sys.stderr)

    # 검증 실패 시 CI에서 감지할 수 있도록 exit code 반환
    if cbom.get("pqc_status") == "DYNAMIC_ANALYSIS_FAILED":
        sys.exit(2)

    validation = cbom.get("validation", {})
    if not validation.get("consistent", True):
        if args.strict_validation:
            sys.exit(3)
        warnings = validation.get("warnings", [])
        if warnings:
            print("\n[WARN] validation mismatch (strict mode off)", file=sys.stderr)
            for msg in warnings:
                print(f"- {msg}", file=sys.stderr)


if __name__ == "__main__":
    main()
