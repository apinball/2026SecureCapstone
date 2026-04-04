"""
TLS Termination CBOM Generator (CycloneDX 1.6)
=================================================
nginx TLS 설정(정적 분석) + 실제 핸드셰이크/인증서 정보(동적 분석)를 결합해
TLS Termination 범위의 암호 자산을 CycloneDX 1.6 CBOM(JSON)으로 기록한다.

CycloneDX 1.6 spec: https://cyclonedx.org/docs/1.6/json/
OWASP Dependency-Track, cdxgen, grype 등 생태계 도구와 호환된다.

repo 기준:
- nginx stage 설정 파일: nginx/nginx-ecc.conf, nginx/nginx-hybrid.conf, nginx/nginx-pq.conf
- tester 컨테이너: tls-tester  (curl 기반 tls_check.sh)
- server 컨테이너: pqc-proxy
- 기본 검증 호스트: proxy-server
- tls_check.sh 실행 방식: docker exec tls-tester tls_check.sh proxy-server 443 <stage>

CI 파이프라인 연동 (devsecops-pipeline.yml Step 10):
  python policy/cbom_gen.py --stage $STAGE --out artifacts/cbom_stage${STAGE}.json

로컬 실행 예시:
  python policy/cbom_gen.py --stage 2 --out artifacts/cbom_stage2.json

CycloneDX CLI로 검증:
  cyclonedx validate --input-file artifacts/cbom_stage2.json --spec-version 1.6

Exit codes:
  0 - 정상
  2 - 동적 분석 실패 (검증 스크립트 오류 포함)
  3 - 교차 검증 불일치 (--strict-validation 시)
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ── 상수 ──────────────────────────────────────────────────────────────────────
GENERATOR_NAME = "cbom_gen.py"
GENERATOR_VERSION = "2.2.1"

CYCLONEDX_SCHEMA_MAP = {
    "1.6": "https://cyclonedx.org/schema/bom-1.6.schema.json",
}

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
    "1", "true", "yes", "on",
}
DEFAULT_SPEC_VERSION = os.getenv("CYCLONEDX_SPEC_VERSION", "1.6")
DEFAULT_REDACT = os.getenv("CBOM_REDACT", "true").strip().lower() not in {
    "0", "false", "no", "off",
}


# ── PQC 알고리즘 패턴 ────────────────────────────────────────────────────────
# Stage 2: X25519 + MLKEM 하이브리드 — [_\s]* 로 구분자 유무 모두 커버
HYBRID_PQC_PATTERNS = [
    re.compile(r"x25519[_\s-]*ml[-_\s]?kem", re.IGNORECASE),
]
# Stage 3: P-curve + MLKEM 또는 순수 PQC
# 두 번째 패턴은 negative lookbehind로 하이브리드 문자열 내 오매칭을 방지
PURE_PQC_PATTERNS = [
    re.compile(r"p\d+[_\s-]*ml[-_\s]?kem", re.IGNORECASE),
    re.compile(r"(?<![a-zA-Z\d])ml[-_\s]?kem[-_\s]?\d+", re.IGNORECASE),
]

PQC_CERT_ALGORITHMS = [
    "dilithium", "ml-dsa", "mldsa",
    "falcon", "sphincs", "slh-dsa", "slhdsa",
]

TLS_GROUP_ALIASES = {
    "x25519": "X25519",
    "prime256v1": "ECDH-P-256",
    "secp256r1": "ECDH-P-256",
    "secp384r1": "ECDH-P-384",
    "secp521r1": "ECDH-P-521",
}

RELATED_ASSET_TYPE_MAP = {
    "algorithm": "algorithm",
    "public-key": "publicKey",
    "private-key": "privateKey",
}

MLKEM_NAME_PATTERN = re.compile(r"ml[-_ ]?kem[-_ ]?(\d+)", re.IGNORECASE)
SHA_ALGO_PATTERN = re.compile(r"(?<![a-zA-Z\d])sha[-_ ]?\d+(?![a-zA-Z\d])", re.IGNORECASE)

# ── TLS directive 파싱 패턴 (정적/컨테이너 분석 공용) ─────────────────────────
TLS_DIRECTIVE_PATTERNS = {
    "ssl_protocols": (r"ssl_protocols\s+([^;]+);", "space"),
    "ssl_ciphers": (r"ssl_ciphers\s+([^;]+);", "colon_or_space"),
    "ssl_ecdh_curve": (r"ssl_ecdh_curve\s+([^;]+);", "colon_or_space"),
    "ssl_certificate": (r"ssl_certificate\s+([^;]+);", "raw"),
    "ssl_certificate_key": (r"ssl_certificate_key\s+([^;]+);", "raw"),
}


# ═══════════════════════════════════════════════════════════════════════════════
# 유틸리티
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_stage(stage: str) -> str:
    """stage 인자를 정규화된 숫자 문자열로 변환."""
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
            cmd, capture_output=True, encoding="utf-8", timeout=timeout,
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
            "stdout": "", "stderr": "",
            "error": "command_not_found",
        }


def resolve_config_path(stage: str, config_path: str) -> str:
    if config_path:
        return config_path
    return STAGE_CONFIG_MAP.get(stage, "nginx/nginx.conf")


def split_directive_value(raw: str, mode: str) -> list:
    if mode == "colon_or_space":
        return [x.strip() for x in re.split(r"[:\s]+", raw) if x.strip()]
    if mode == "space":
        return [x.strip() for x in raw.split() if x.strip()]
    return [raw.strip()]


def _parse_directives(config_text: str, patterns: dict) -> dict:
    findings = {}
    for key, (pattern, mode) in patterns.items():
        m = re.search(pattern, config_text, re.MULTILINE)
        if not m:
            continue
        raw = m.group(1).strip()
        findings[key] = raw if mode == "raw" else split_directive_value(raw, mode)
    return findings


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._@+=-]+", "-", (value or "").strip())
    return re.sub(r"-+", "-", cleaned).strip("-") or "unknown"


def stable_redacted_suffix(value: str, length: int = 8) -> str:
    raw = (value or "").encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:length]


def dedupe_keep_order(values: list) -> list:
    seen = set()
    return [x for x in (values or []) if x not in seen and not seen.add(x)]


def parse_openssl_time(value: str) -> str | None:
    if not value:
        return None
    normalized = re.sub(r"\s+", " ", value.strip())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(normalized, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            continue
    return None


def prune_none(value):
    if isinstance(value, dict):
        return {
            k: pruned for k, v in value.items()
            if (pruned := prune_none(v)) is not None and pruned != {} and pruned != []
        }
    if isinstance(value, list):
        return [
            pruned for v in value
            if (pruned := prune_none(v)) is not None and pruned != {} and pruned != []
        ]
    return value


# ═══════════════════════════════════════════════════════════════════════════════
# CycloneDX 빌더 헬퍼
# ═══════════════════════════════════════════════════════════════════════════════

def make_property(name: str, value) -> dict | None:
    if value is None:
        return None
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False)
    else:
        rendered = str(value)
    return {"name": name, "value": rendered}


def append_properties(target: dict, *properties: dict | None):
    props = [p for p in properties if p is not None]
    if props:
        target.setdefault("properties", []).extend(props)


def add_component(components_by_ref: dict, component: dict):
    component = prune_none(component)
    ref = component.get("bom-ref")
    if not ref:
        raise ValueError("CycloneDX component에는 bom-ref가 필요합니다.")
    existing = components_by_ref.get(ref)
    if not existing:
        components_by_ref[ref] = component
        return
    for key, value in component.items():
        if key == "properties":
            existing.setdefault("properties", []).extend(value)
        elif key == "cryptoProperties":
            existing.setdefault("cryptoProperties", {})
            for ck, cv in value.items():
                if isinstance(cv, list):
                    existing["cryptoProperties"].setdefault(ck, []).extend(cv)
                elif isinstance(cv, dict):
                    existing["cryptoProperties"].setdefault(ck, {})
                    for dk, dv in cv.items():
                        if isinstance(dv, list):
                            existing["cryptoProperties"][ck].setdefault(dk, []).extend(dv)
                        else:
                            existing["cryptoProperties"][ck].setdefault(dk, dv)
                else:
                    existing["cryptoProperties"].setdefault(ck, cv)
        else:
            existing.setdefault(key, value)


def add_dependency(dependencies: list, ref: str, depends_on=None):
    depends_on = dedupe_keep_order(depends_on or [])
    if not depends_on:
        return
    for item in dependencies:
        if item.get("ref") == ref:
            item.setdefault("dependsOn", [])
            item["dependsOn"] = dedupe_keep_order(item["dependsOn"] + depends_on)
            return
    dependencies.append({"ref": ref, "dependsOn": depends_on})


# ═══════════════════════════════════════════════════════════════════════════════
# CycloneDX 컴포넌트 빌더
# ═══════════════════════════════════════════════════════════════════════════════

def protocol_version_only(raw: str) -> str | None:
    if not raw:
        return None
    m = re.search(r"TLSv?(\d+(?:\.\d+)?)", raw, re.IGNORECASE)
    return m.group(1) if m else None


def protocol_name(raw: str, configured: list) -> str:
    if raw:
        return raw.strip()
    return configured[0] if configured else "TLS"


def make_related_asset(asset_type: str, ref: str) -> dict:
    rendered_type = RELATED_ASSET_TYPE_MAP.get(asset_type, asset_type)
    return {"type": rendered_type, "ref": ref}


def dedupe_related_assets(assets: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for asset in assets or []:
        key = (asset.get("type"), asset.get("ref"))
        if key in seen:
            continue
        seen.add(key)
        result.append(asset)
    return result


def decompose_key_exchange_name(name: str) -> dict:
    raw = (name or "").strip()
    lower = raw.lower().replace(" ", "")
    if not raw:
        return {"display_name": raw, "children": []}

    mlkem = MLKEM_NAME_PATTERN.search(lower)
    if mlkem:
        children = []
        if "x25519" in lower:
            children.append("X25519")
        else:
            p_match = re.search(r"p[-_ ]?(\d+)", lower)
            if p_match:
                children.append(f"ECDH-P-{p_match.group(1)}")
        children.append(f"ML-KEM-{mlkem.group(1)}")
        return {"display_name": raw, "children": dedupe_keep_order(children)}

    canonical = TLS_GROUP_ALIASES.get(lower)
    if canonical:
        return {"display_name": canonical, "children": [canonical]}

    if re.fullmatch(r"x\d+", lower):
        canonical = lower.upper()
        return {"display_name": canonical, "children": [canonical]}

    p_match = re.fullmatch(r"p[-_ ]?(\d+)", lower)
    if p_match:
        canonical = f"ECDH-P-{p_match.group(1)}"
        return {"display_name": canonical, "children": [canonical]}

    return {"display_name": raw, "children": [raw]}


def extract_cipher_suite_algorithms(cipher_suite: str) -> list[str]:
    suite = (cipher_suite or "").strip()
    if not suite:
        return []
    upper = suite.upper().replace("-", "_")
    algorithms = []

    if "CHACHA20_POLY1305" in upper:
        algorithms.append("ChaCha20-Poly1305")
    aes_gcm = re.search(r"AES[_-]?(\d{3})[_-]?GCM", upper)
    if aes_gcm:
        algorithms.append(f"AES-{aes_gcm.group(1)}-GCM")
    aes_ccm = re.search(r"AES[_-]?(\d{3})[_-]?CCM", upper)
    if aes_ccm:
        algorithms.append(f"AES-{aes_ccm.group(1)}-CCM")
    sha_match = re.search(r"SHA[_-]?(\d{3})", upper)
    if sha_match:
        algorithms.append(f"SHA{sha_match.group(1)}")
    if "ECDHE" in upper:
        algorithms.append("ECDHE")
    if re.search(r"(^|_)RSA(_|$)", upper):
        algorithms.append("RSA")
    if "ECDSA" in upper:
        algorithms.append("ECDSA")

    mlkem_match = MLKEM_NAME_PATTERN.search(upper)
    if mlkem_match:
        algorithms.append(f"ML-KEM-{mlkem_match.group(1)}")

    # TODO: PQC TLS cipher suite naming이 최종 표준화되면 KEM/서명/대칭 구성요소 매핑을 확장한다.
    return dedupe_keep_order(algorithms)


def infer_algorithm_properties(name: str, context: str = "") -> dict:
    lower = (name or "").lower()
    props = {"executionEnvironment": "software-plain-ram", "implementationPlatform": "generic"}

    mlkem_match = MLKEM_NAME_PATTERN.search(lower)
    has_mlkem = bool(mlkem_match)
    has_curve = (
        "x25519" in lower
        or "ecdh" in lower
        or bool(re.search(r"p[-_ ]?(\d+)", lower))
    )

    if has_mlkem and has_curve:
        props["primitive"] = "combiner"
    elif has_mlkem:
        props["primitive"] = "kem"
    elif "x25519" in lower or "ecdh" in lower:
        props["primitive"] = "key-agree"
    elif any(t in lower for t in (
        "rsa", "ecdsa", "ed25519", "ed448",
        "dilithium", "ml-dsa", "falcon", "sphincs", "slh-dsa",
    )):
        props["primitive"] = "signature"
    elif "aes" in lower or ("chacha20" in lower and "poly1305" in lower):
        props["primitive"] = "aead"
    elif SHA_ALGO_PATTERN.search(lower):
        props["primitive"] = "digest"

    if mlkem_match:
        props["parameterSetIdentifier"] = mlkem_match.group(1)
        props["algorithmFamily"] = "ML-KEM"
    if not has_mlkem:
        x_match = re.search(r"x(\d+)", lower)
        if x_match:
            props.setdefault("parameterSetIdentifier", x_match.group(1))
    p_match = re.search(r"p[-_ ]?(\d+)", lower)
    if p_match:
        props["curve"] = f"P-{p_match.group(1)}"
    rsa_match = re.search(r"rsa[^\d]*(\d{3,5})", lower)
    if rsa_match:
        props.setdefault("parameterSetIdentifier", rsa_match.group(1))
        props.setdefault("algorithmFamily", "RSA")
    if lower.startswith("ecdsa"):
        props.setdefault("algorithmFamily", "ECDSA")
    if "aes" in lower:
        props.setdefault("algorithmFamily", "AES")
    if "chacha20" in lower and "poly1305" in lower:
        props.setdefault("algorithmFamily", "ChaCha20-Poly1305")
    if SHA_ALGO_PATTERN.search(lower):
        props.setdefault("algorithmFamily", "SHA")

    if context == "certificate-signature":
        props.setdefault("cryptoFunctions", ["sign", "verify"])
    elif context == "key-exchange":
        props.setdefault(
            "cryptoFunctions",
            ["encapsulate", "decapsulate"] if props.get("primitive") == "kem" else ["keygen", "keyderive"],
        )
    elif context == "public-key":
        props.setdefault("cryptoFunctions", ["verify"])
    elif context == "cipher-suite":
        if props.get("primitive") == "aead":
            props.setdefault("cryptoFunctions", ["encrypt", "decrypt"])
        elif props.get("primitive") == "digest":
            props.setdefault("cryptoFunctions", ["digest"])
    return prune_none(props)


def build_algorithm_component(name, context="", extra_properties=None):
    ref = f"crypto/algorithm/{slugify(name)}"
    comp = {
        "bom-ref": ref, "type": "cryptographic-asset", "name": name,
        "cryptoProperties": {"assetType": "algorithm",
                             "algorithmProperties": infer_algorithm_properties(name, context)},
    }
    for p in extra_properties or []:
        append_properties(comp, p)
    return ref, prune_none(comp)


def build_certificate_component(cert_f, cert_alg_ref, pk_ref, cert_path, *, redact=True):
    if not cert_f:
        return None, None
    subject = cert_f.get("subject") or "server-certificate"
    serial = cert_f.get("serial") or "unknown"
    ref = f"crypto/certificate/{slugify(subject)}@{slugify(serial)}"
    related = []
    if cert_alg_ref:
        related.append(make_related_asset("algorithm", cert_alg_ref))
    if pk_ref:
        related.append(make_related_asset("public-key", pk_ref))
    comp = {
        "bom-ref": ref, "type": "cryptographic-asset", "name": subject,
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "serialNumber": cert_f.get("serial"),
                "subjectName": subject,
                "issuerName": cert_f.get("issuer"),
                "notValidBefore": parse_openssl_time(cert_f.get("not_before")),
                "notValidAfter": parse_openssl_time(cert_f.get("not_after")),
                "certificateFormat": "X.509",
                "certificateFileExtension": Path(cert_path).suffix.lstrip(".") if cert_path else None,
                "relatedCryptographicAssets": {"assets": dedupe_related_assets(related)} if related else None,
            },
        },
    }
    append_properties(comp,
                      make_property("securecapstone:cert:is_pqc", cert_f.get("is_pqc_certificate")),
                      make_property("securecapstone:cert:pqc_note", cert_f.get("cert_pqc_note")),
                      None if redact else make_property("securecapstone:cert:path", cert_path))
    return ref, prune_none(comp)


def build_public_key_component(cert_f, pk_alg_ref):
    bits = cert_f.get("public_key_bits")
    if not bits and not pk_alg_ref:
        return None, None
    name = cert_f.get("public_key_algorithm") or f"public-key-{bits or 'unknown'}"
    ref = f"crypto/key/{slugify(name)}-{bits or 'unknown'}"
    related = [make_related_asset("algorithm", pk_alg_ref)] if pk_alg_ref else []
    comp = {
        "bom-ref": ref, "type": "cryptographic-asset", "name": name,
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": "public-key", "state": "active", "size": bits,
                "relatedCryptographicAssets": {"assets": dedupe_related_assets(related)} if related else None,
                "securedBy": {"mechanism": "Software"},
            },
        },
    }
    append_properties(comp, make_property("securecapstone:key:origin", "certificate-subject-public-key"))
    return ref, prune_none(comp)


def build_private_key_component(path, bits, pk_alg_ref, *, redact=True):
    if not path:
        return None, None
    ref_slug = Path(path).name if redact else path
    if redact:
        ref = f"crypto/key/{slugify(ref_slug)}-{stable_redacted_suffix(path)}"
    else:
        ref = f"crypto/key/{slugify(ref_slug)}"
    related = [make_related_asset("algorithm", pk_alg_ref)] if pk_alg_ref else []
    comp = {
        "bom-ref": ref, "type": "cryptographic-asset",
        "name": Path(path).name if redact else path,
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": "private-key", "state": "active", "size": bits,
                "relatedCryptographicAssets": {"assets": dedupe_related_assets(related)} if related else None,
                "securedBy": {"mechanism": "Software"},
            },
        },
    }
    append_properties(
        comp,
        make_property("securecapstone:key:size_inferred_from_certificate", bits is not None),
        None if redact else make_property("securecapstone:key:path", path),
    )
    return ref, prune_none(comp)


def build_protocol_component(
    cfg_protos,
    cfg_ciphers,
    cfg_kex,
    neg_proto,
    neg_cipher,
    neg_kex,
    related_assets,
    suite_algorithms=None,
):
    name = protocol_name(neg_proto, cfg_protos)
    ref = f"crypto/protocol/{slugify(name)}"
    suites = dedupe_keep_order(([neg_cipher] if neg_cipher else []) + (cfg_ciphers or []))
    groups = dedupe_keep_order(([neg_kex] if neg_kex else []) + (cfg_kex or []))
    suite_algorithms = suite_algorithms or {}

    cipher_suites = []
    for suite in suites:
        entry = {"name": suite}
        alg_refs = dedupe_keep_order(suite_algorithms.get(suite, []))
        if alg_refs:
            entry["algorithms"] = alg_refs
        if neg_kex and neg_cipher and suite == neg_cipher:
            entry["tlsGroups"] = [neg_kex]
        elif not neg_cipher and len(groups) == 1:
            entry["tlsGroups"] = groups
        cipher_suites.append(entry)

    comp = {
        "bom-ref": ref, "type": "cryptographic-asset", "name": name,
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "type": "tls", "version": protocol_version_only(name),
                "cipherSuites": cipher_suites,
                "relatedCryptographicAssets": {
                    "assets": dedupe_related_assets(related_assets)
                } if related_assets else None,
            },
        },
    }
    append_properties(comp,
                      make_property("securecapstone:protocol:configured", cfg_protos),
                      make_property("securecapstone:protocol:negotiated", neg_proto),
                      make_property("securecapstone:protocol:configured_groups", cfg_kex),
                      make_property("securecapstone:protocol:negotiated_group", neg_kex))
    return ref, prune_none(comp)


def extract_root_property(bom: dict, name: str):
    for p in bom.get("properties", []):
        if p.get("name") == name:
            return p.get("value")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 정적 / 동적 분석
# ═══════════════════════════════════════════════════════════════════════════════

def static_analysis(config_path: str) -> dict:
    result = {"method": "static", "source": config_path, "findings": {}, "notes": []}
    try:
        text = Path(config_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        result["error"] = f"{config_path} 파일 없음"
        return result
    except OSError as e:
        result["error"] = f"{config_path} 읽기 실패: {e}"
        return result

    result["findings"] = parse_nginx_directives(text)

    if re.search(r"^\s*include\s+", text, re.MULTILINE):
        result["notes"].append(
            "로컬 nginx 설정에 include가 있어 단일 파일 정적 분석만으로는 실제 적용값과 다를 수 있습니다."
        )

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


def read_container_config(server_container, config_path="/opt/nginx/nginx-conf/nginx.conf"):
    dump_cmd = ["docker", "exec", server_container, "nginx", "-T"]
    dump = run_cmd(dump_cmd, timeout=15)
    dump_text = dump.get("stdout") or ""
    if dump.get("stderr"):
        dump_text += ("\n" if dump_text else "") + dump["stderr"]
    if dump["returncode"] == 0 and dump_text.strip():
        return {"config_text": dump_text, "source": "nginx -T"}

    cmd = ["docker", "exec", server_container, "cat", config_path]
    r = run_cmd(cmd, timeout=10)
    if r.get("error") or r["returncode"] != 0:
        return {"error": f"컨테이너 설정 읽기 실패: {(r.get('stderr') or r.get('stdout') or dump.get('stderr') or dump.get('stdout') or '').strip()}"}
    return {"config_text": r["stdout"], "source": config_path}


def strip_nginx_comments(config_text: str) -> str:
    lines = []
    for line in config_text.splitlines():
        in_single = False
        in_double = False
        escaped = False
        rendered = []
        for ch in line:
            if escaped:
                rendered.append(ch)
                escaped = False
                continue
            if ch == "\\":
                rendered.append(ch)
                escaped = True
                continue
            if ch == '"' and not in_single:
                in_double = not in_double
                rendered.append(ch)
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
                rendered.append(ch)
                continue
            if ch == "#" and not in_single and not in_double:
                break
            rendered.append(ch)
        lines.append("".join(rendered).rstrip())
    return "\n".join(lines)


def parse_nginx_directives(config_text: str) -> dict:
    normalized = strip_nginx_comments(config_text)
    findings = {}
    for key, (pattern, mode) in TLS_DIRECTIVE_PATTERNS.items():
        matches = [m.group(1).strip() for m in re.finditer(pattern, normalized, re.MULTILINE)]
        if not matches:
            continue
        if mode == "raw":
            findings[key] = matches[-1]
        else:
            values = []
            for raw in matches:
                values.extend(split_directive_value(raw, mode))
            findings[key] = dedupe_keep_order(values)
    return findings


def classify_stage(key_group: str) -> str:
    g = (key_group or "").strip()
    if not g:
        return "UNKNOWN"
    for p in HYBRID_PQC_PATTERNS:
        if p.search(g):
            return "STAGE_2_HYBRID_PQC"
    for p in PURE_PQC_PATTERNS:
        if p.search(g):
            return "STAGE_3_POST_QUANTUM"
    return "STAGE_1_CLASSICAL"


def parse_verify_tls_output(output: str) -> dict:
    """verify_tls.sh / tls_check.sh 출력을 파싱.

    주의: Stage 3에서는 "판정:" 라인이 2개 출력되므로 마지막 매칭을 사용한다.
    """
    result = {}
    first_match_patterns = [
        (r"Protocol\s*(?:version)?\s*:\s*(.+)", "negotiated_protocol"),
        (r"Cipher(?:suite)?\s*:\s*(.+)", "negotiated_cipher"),
        (r"Key Group\s*:\s*(.+)", "key_exchange_actual"),
        (r"^Group\s*:\s*(.+)", "key_exchange_actual"),
        (r"Negotiated TLS[\d.]+ group\s*:\s*(.+)", "key_exchange_actual"),
        (r"Server Temp Key\s*:\s*(.+)", "key_exchange_actual"),
        (r"Peer Temp Key\s*:\s*(.+)", "key_exchange_actual"),
    ]
    for pattern, key in first_match_patterns:
        m = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
        if m and key not in result:
            val = m.group(1).strip()
            if val.lower() != "unknown":
                result[key] = val

    # "판정:" 패턴은 마지막 매칭을 사용 (Stage 3에서 최종 판정 라인 캡처)
    judgement_matches = re.findall(r"판정\s*:\s*(.+)", output)
    if judgement_matches:
        final = judgement_matches[-1].strip()
        if final.lower() != "unknown":
            result["verify_tls_judgement"] = final

    # tls_check.sh 형식: "[PASS] Stage 2 policy satisfied." / "[FAIL] ..."
    if "verify_tls_judgement" not in result:
        m = re.search(r"\[PASS\].*Stage\s*(\d+)", output)
        if m:
            result["verify_tls_judgement"] = f"Stage {m.group(1)} - policy satisfied"
        elif re.search(r"\[FAIL\]", output):
            result["verify_tls_judgement"] = "fail"

    return result


def parse_cert_info(cert_text: str) -> dict:
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

    sig_alg = result.get("cert_signature_algorithm", "").lower()
    pk_alg = result.get("public_key_algorithm", "").lower()
    is_pqc = any(pqc in f"{sig_alg} {pk_alg}" for pqc in PQC_CERT_ALGORITHMS)
    result["is_pqc_certificate"] = is_pqc
    if not is_pqc:
        result["cert_pqc_note"] = (
            "인증서 서명/공개키가 전통적 알고리즘(RSA/ECDSA)입니다. "
            "TLS 키 교환이 PQC라도 인증서 자체는 양자 내성이 아닙니다.")
    return result


def cross_validate(our_status, script_judgement, requested_stage, *, strict=False):
    """교차 검증. strict=True이면 판정 파싱 실패 시에도 consistent=False."""
    validation = {"consistent": True, "warnings": []}
    if not script_judgement:
        validation["warnings"].append("검증 스크립트 판정 결과를 파싱하지 못했습니다.")
        if strict:
            validation["consistent"] = False
            validation["warnings"].append("엄격 모드: 판정 결과를 확인할 수 없으므로 검증 실패로 처리합니다.")
        return validation

    jl = script_judgement.lower()
    if "stage 3" in jl:
        script_stage = "3"
    elif "stage 2" in jl:
        script_stage = "2"
    elif "stage 1" in jl:
        script_stage = "1"
    elif "pqc" in jl and "hybrid" not in jl:
        script_stage = "3"
    else:
        script_stage = None

    our_stage = {"STAGE_1_CLASSICAL": "1", "STAGE_2_HYBRID_PQC": "2", "STAGE_3_POST_QUANTUM": "3"}.get(our_status)

    if script_stage and our_stage and script_stage != our_stage:
        validation["consistent"] = False
        validation["warnings"].append(
            f"판정 불일치: 검증 스크립트는 Stage {script_stage}, cbom_gen은 {our_status}으로 판정했습니다. "
            "파싱 로직 또는 알고리즘 매핑을 확인하세요.")
    if requested_stage in ("1", "2", "3") and our_stage and requested_stage != our_stage:
        validation["consistent"] = False
        validation["warnings"].append(
            f"요청 Stage({requested_stage})와 실제 협상 결과(Stage {our_stage})가 다릅니다. "
            "서버 설정이 올바르게 적용되었는지 확인하세요.")
    if not validation["warnings"]:
        del validation["warnings"]
    return validation


def dynamic_analysis(host, port, tester_container, server_container, server_cert_path, stage, verify_script):
    """docker exec으로 TLS 핸드셰이크 검증 및 인증서 정보를 수집.

    verify 스크립트가 실패(non-zero exit)하면 error를 그대로 유지한다.
    부분 파싱은 참고용으로만 보존.
    """
    result = {
        "method": "dynamic", "target": f"{host}:{port}",
        "tester": tester_container, "server": server_container, "findings": {},
    }
    verify_cmd = ["docker", "exec", tester_container, verify_script, host, str(port), stage]
    verify = run_cmd(verify_cmd, timeout=30)
    result["verify_command"] = verify["cmd"]
    result["verify_exit_code"] = verify["returncode"]

    if verify.get("error") == "command_not_found":
        result["error"] = "docker 또는 검증 스크립트 명령어를 찾을 수 없습니다"
        result["findings"]["raw_output"] = verify["stdout"] + verify["stderr"]
        return result

    combined = verify["stdout"]
    if verify["stdout"] and verify["stderr"]:
        combined += "\n"
    combined += verify["stderr"]
    result["findings"]["raw_output"] = combined

    if verify.get("error") == "timeout":
        result["error"] = "TLS 검증 타임아웃 (30초 초과)"
    elif verify["returncode"] != 0:
        result["error"] = f"TLS 검증 실패 (exit code: {verify['returncode']})"

    parsed = parse_verify_tls_output(combined)
    result["findings"].update(parsed)
    # error→warning 강등 없음: 검증 실패는 실패다

    # ── 인증서 정보 수집 ──
    cert_cmd = [
        "docker", "exec", server_container, "openssl", "x509",
        "-in", server_cert_path, "-noout", "-subject", "-issuer", "-serial", "-dates", "-text",
    ]
    cert = run_cmd(cert_cmd, timeout=15)
    result["cert_command"] = cert["cmd"]
    if cert.get("error") == "command_not_found":
        result["cert_error"] = "docker 또는 openssl 명령어를 찾을 수 없습니다"
    elif cert.get("error") == "timeout":
        result["cert_error"] = "인증서 정보 조회 타임아웃"
    elif cert["returncode"] == 0:
        ct = cert["stdout"]
        if cert["stdout"] and cert["stderr"]:
            ct += "\n"
        ct += cert["stderr"]
        result["findings"]["certificate"] = parse_cert_info(ct)
    else:
        result["cert_error"] = (cert["stderr"] or cert["stdout"]).strip()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 스냅샷 → CycloneDX 변환
# ═══════════════════════════════════════════════════════════════════════════════

def build_analysis_snapshot(
    host=DEFAULT_HOST, port=DEFAULT_PORT, stage="auto", config_path="",
    tester_container=DEFAULT_TESTER, server_container=DEFAULT_SERVER,
    server_cert_path=DEFAULT_CERT_PATH, verify_script=DEFAULT_VERIFY_SCRIPT,
    strict=False,
):
    normalized_stage = normalize_stage(stage)
    resolved_config = resolve_config_path(normalized_stage, config_path)

    static = static_analysis(resolved_config)

    container_conf = read_container_config(server_container)
    container_findings = None
    if "config_text" in container_conf:
        static["container_config_available"] = True
        container_findings = parse_nginx_directives(container_conf["config_text"])
        local_findings = static.get("findings", {})
        for key in ("ssl_protocols", "ssl_ciphers", "ssl_ecdh_curve", "ssl_certificate", "ssl_certificate_key"):
            lv, cv = local_findings.get(key), container_findings.get(key)
            if lv is not None and cv is not None and lv != cv:
                static.setdefault("notes", []).append(
                    f"로컬 설정의 {key}({lv})와 컨테이너 내부 설정({cv})이 다릅니다. "
                    "CI에서 nginx.conf가 교체되었을 수 있습니다.")
    else:
        static["container_config_available"] = False

    dynamic = dynamic_analysis(
        host, port, tester_container, server_container, server_cert_path, normalized_stage, verify_script)

    static_f = static.get("findings", {})
    dynamic_f = dynamic.get("findings", {})
    cert_f = dynamic_f.get("certificate", {})

    # effective_static: 컨테이너 설정이 있으면 우선 적용
    effective = dict(static_f)
    if container_findings is not None:
        for key in ("ssl_protocols", "ssl_ciphers", "ssl_ecdh_curve", "ssl_certificate", "ssl_certificate_key"):
            if container_findings.get(key) is not None:
                effective[key] = container_findings[key]

    key_exchange = dynamic_f.get("key_exchange_actual", "")
    if dynamic.get("error"):
        pqc_status = "DYNAMIC_ANALYSIS_FAILED"
        partial = classify_stage(key_exchange) if key_exchange else None
    else:
        pqc_status = classify_stage(key_exchange)
        partial = None

    validation = cross_validate(
        our_status=pqc_status if pqc_status != "DYNAMIC_ANALYSIS_FAILED" else (partial or pqc_status),
        script_judgement=dynamic_f.get("verify_tls_judgement", ""),
        requested_stage=normalized_stage,
        strict=strict,
    )

    snapshot = {
        "generated_at": iso_utc_now(),
        "generator": GENERATOR_NAME,
        "target": {"host": host, "port": port, "stage_requested": normalized_stage, "scope": "TLS Termination"},
        "pqc_status": pqc_status,
        "validation": validation,
        "crypto_assets": {
            "configured_protocols": effective.get("ssl_protocols", []),
            "configured_ciphers": effective.get("ssl_ciphers", static_f.get("ssl_ciphers", [])),
            "configured_key_exchange": effective.get("ssl_ecdh_curve", []),
            "certificate_path": effective.get("ssl_certificate"),
            "private_key_path": effective.get("ssl_certificate_key"),
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
        "analysis_detail": {"static": static, "dynamic": dynamic},
    }
    if partial:
        snapshot["partial_classification"] = partial
    return snapshot


def convert_snapshot_to_cyclonedx(snapshot, spec_version=DEFAULT_SPEC_VERSION, *, redact=True):
    ca = snapshot.get("crypto_assets", {})
    ad = snapshot.get("analysis_detail", {})
    static, dynamic = ad.get("static", {}), ad.get("dynamic", {})
    cert_f = dynamic.get("findings", {}).get("certificate", {})

    cfg_protos = dedupe_keep_order(ca.get("configured_protocols", []))
    cfg_ciphers = dedupe_keep_order(ca.get("configured_ciphers", []))
    cfg_kex = dedupe_keep_order(ca.get("configured_key_exchange", []))
    neg_proto = ca.get("negotiated_protocol")
    neg_cipher = ca.get("negotiated_cipher")
    neg_kex = ca.get("negotiated_key_exchange")

    host = snapshot.get("target", {}).get("host", DEFAULT_HOST)
    port = snapshot.get("target", {}).get("port", DEFAULT_PORT)
    stage_req = snapshot.get("target", {}).get("stage_requested")
    pqc_status = snapshot.get("pqc_status")
    validation = snapshot.get("validation", {})

    root_ref = f"target/tls-termination/{slugify(host)}:{port}"
    root_comp = {
        "bom-ref": root_ref, "type": "application",
        "name": f"TLS Termination Endpoint ({host}:{port})",
        "version": f"stage-{stage_req}" if stage_req else None,
        "description": "Observed TLS termination configuration and runtime cryptographic assets.",
    }
    append_properties(root_comp,
                      make_property("securecapstone:scope", snapshot.get("target", {}).get("scope")),
                      make_property("securecapstone:host", host),
                      make_property("securecapstone:port", port))

    comps, deps = {}, []
    root_refs = []
    proto_related_assets = []
    suite_algorithms = {}

    def register_component(ref, comp, *, root=False, related_type=None):
        if not ref or not comp:
            return
        add_component(comps, comp)
        if root:
            root_refs.append(ref)
        if related_type:
            proto_related_assets.append(make_related_asset(related_type, ref))

    for name, source in [(n, "configured") for n in cfg_kex] + ([(neg_kex, "negotiated")] if neg_kex else []):
        parsed = decompose_key_exchange_name(name)
        child_refs = []
        for child_name in parsed["children"]:
            child_ref, child_comp = build_algorithm_component(
                child_name,
                "key-exchange",
                [
                    make_property("securecapstone:source", source),
                    make_property("securecapstone:key_exchange:group", name),
                ],
            )
            register_component(child_ref, child_comp, root=True, related_type="algorithm")
            child_refs.append(child_ref)

        display_name = parsed["display_name"] or name
        child_unique = dedupe_keep_order(parsed["children"])
        is_composite = len(child_unique) > 1 or display_name != (child_unique[0] if child_unique else display_name)
        if is_composite:
            group_ref, group_comp = build_algorithm_component(
                display_name,
                "key-exchange",
                [
                    make_property("securecapstone:source", source),
                    make_property("securecapstone:key_exchange:group", name),
                    make_property("securecapstone:key_exchange:decomposed", child_unique),
                ],
            )
            register_component(group_ref, group_comp, root=True, related_type="algorithm")
            if child_refs:
                add_dependency(deps, group_ref, child_refs)

    cert_sig_ref = None
    if ca.get("cert_signature_algorithm"):
        cert_sig_ref, c = build_algorithm_component(ca["cert_signature_algorithm"], "certificate-signature")
        register_component(cert_sig_ref, c, root=True, related_type="algorithm")

    pk_alg_ref = None
    if ca.get("cert_public_key_algorithm"):
        pk_alg_ref, c = build_algorithm_component(ca["cert_public_key_algorithm"], "public-key")
        register_component(pk_alg_ref, c, root=True, related_type="algorithm")

    pk_ref, pk_c = build_public_key_component(cert_f, pk_alg_ref)
    if pk_c:
        register_component(pk_ref, pk_c, root=True, related_type="public-key")
        if pk_alg_ref:
            add_dependency(deps, pk_ref, [pk_alg_ref])

    sk_ref, sk_c = build_private_key_component(ca.get("private_key_path"), ca.get("cert_public_key_bits"), pk_alg_ref, redact=redact)
    if sk_c:
        register_component(sk_ref, sk_c, root=True, related_type="private-key")
        if pk_alg_ref:
            add_dependency(deps, sk_ref, [pk_alg_ref])

    cert_ref, cert_c = build_certificate_component(cert_f, cert_sig_ref, pk_ref, ca.get("certificate_path"), redact=redact)
    if cert_c:
        register_component(cert_ref, cert_c, root=True)
        cd = [r for r in (cert_sig_ref, pk_ref) if r]
        if cd:
            add_dependency(deps, cert_ref, cd)

    for suite in dedupe_keep_order(([neg_cipher] if neg_cipher else []) + cfg_ciphers):
        alg_refs = []
        for alg_name in extract_cipher_suite_algorithms(suite):
            alg_ref, alg_comp = build_algorithm_component(
                alg_name,
                "cipher-suite",
                [make_property("securecapstone:cipher_suite", suite)],
            )
            register_component(alg_ref, alg_comp, root=True, related_type="algorithm")
            alg_refs.append(alg_ref)
        if alg_refs:
            suite_algorithms[suite] = dedupe_keep_order(alg_refs)

    p_ref, p_c = build_protocol_component(
        cfg_protos,
        cfg_ciphers,
        cfg_kex,
        neg_proto,
        neg_cipher,
        neg_kex,
        proto_related_assets,
        suite_algorithms=suite_algorithms,
    )
    register_component(p_ref, p_c, root=True)
    add_dependency(deps, p_ref, [asset["ref"] for asset in dedupe_related_assets(proto_related_assets)])
    if cert_ref:
        add_dependency(deps, p_ref, [cert_ref])
    add_dependency(deps, root_ref, dedupe_keep_order(root_refs + ([cert_ref] if cert_ref else [])))

    bom_props = [
        make_property("securecapstone:generator", snapshot.get("generator")),
        make_property("securecapstone:scope", snapshot.get("target", {}).get("scope")),
        make_property("securecapstone:stage_requested", stage_req),
        make_property("securecapstone:pqc_status", pqc_status),
        make_property("securecapstone:validation", validation),
    ]
    if snapshot.get("partial_classification"):
        bom_props.append(make_property("securecapstone:partial_classification", snapshot["partial_classification"]))
    if not redact:
        bom_props.extend([
            make_property("securecapstone:analysis_detail:static", static),
            make_property("securecapstone:analysis_detail:dynamic", dynamic),
        ])
    if isinstance(static, dict) and static.get("notes"):
        bom_props.append(make_property("securecapstone:notes:static", static["notes"]))
    if isinstance(dynamic, dict) and dynamic.get("error"):
        bom_props.append(make_property("securecapstone:error:dynamic", dynamic["error"]))

    return prune_none({
        "$schema": CYCLONEDX_SCHEMA_MAP.get(spec_version, f"https://cyclonedx.org/schema/bom-{spec_version}.schema.json"),
        "bomFormat": "CycloneDX", "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": snapshot.get("generated_at") or iso_utc_now(),
            "tools": {"components": [{
                "type": "application", "name": GENERATOR_NAME,
                "version": GENERATOR_VERSION,
                "description": "TLS Termination CBOM Generator (CycloneDX output)",
            }]},
            "component": prune_none(root_comp),
        },
        "components": list(comps.values()),
        "dependencies": deps,
        "properties": prune_none(bom_props),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 메인
# ═══════════════════════════════════════════════════════════════════════════════

def generate_cbom(
    host=DEFAULT_HOST, port=DEFAULT_PORT, stage="auto", config_path="",
    tester_container=DEFAULT_TESTER, server_container=DEFAULT_SERVER,
    server_cert_path=DEFAULT_CERT_PATH, verify_script=DEFAULT_VERIFY_SCRIPT,
    spec_version=DEFAULT_SPEC_VERSION, strict=False, redact=True,
):
    snapshot = build_analysis_snapshot(
        host=host, port=port, stage=stage, config_path=config_path,
        tester_container=tester_container, server_container=server_container,
        server_cert_path=server_cert_path, verify_script=verify_script, strict=strict)
    return convert_snapshot_to_cyclonedx(snapshot, spec_version=spec_version, redact=redact)


def main():
    parser = argparse.ArgumentParser(
        description="TLS Termination CBOM Generator (CycloneDX 1.6 JSON)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python policy/cbom_gen.py --stage 2 --out artifacts/cbom_stage2.json
  python policy/cbom_gen.py --out artifacts/cbom.json
  python policy/cbom_gen.py --stage 3 --strict-validation --no-redact

Exit codes:  0=정상  2=동적분석실패  3=교차검증불일치(strict)
        """)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--stage", default="auto")
    parser.add_argument("--config", default="")
    parser.add_argument("--tester-container", default=DEFAULT_TESTER)
    parser.add_argument("--server-container", default=DEFAULT_SERVER)
    parser.add_argument("--server-cert-path", default=DEFAULT_CERT_PATH)
    parser.add_argument("--verify-script", default=DEFAULT_VERIFY_SCRIPT)
    parser.add_argument("--spec-version", default=DEFAULT_SPEC_VERSION)
    parser.add_argument("--out", default="")
    parser.add_argument("--strict-validation", action=argparse.BooleanOptionalAction, default=DEFAULT_STRICT_VALIDATION)
    parser.add_argument("--redact", action=argparse.BooleanOptionalAction, default=DEFAULT_REDACT,
                        help="BOM에서 내부 경로/분석 상세 제거 (기본: 제거)")
    args = parser.parse_args()

    cbom = generate_cbom(
        host=args.host, port=args.port, stage=args.stage, config_path=args.config,
        tester_container=args.tester_container, server_container=args.server_container,
        server_cert_path=args.server_cert_path, verify_script=args.verify_script,
        spec_version=args.spec_version, strict=args.strict_validation, redact=args.redact)

    text = json.dumps(cbom, indent=2, ensure_ascii=False)
    print(text)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
        print(f"\nCBOM (CycloneDX {args.spec_version}) 저장 완료: {out_path}", file=sys.stderr)

    pqc_status = extract_root_property(cbom, "securecapstone:pqc_status")
    if pqc_status == "DYNAMIC_ANALYSIS_FAILED":
        sys.exit(2)

    val_raw = extract_root_property(cbom, "securecapstone:validation")
    val = {}
    if val_raw:
        try: val = json.loads(val_raw)
        except json.JSONDecodeError: pass
    if not val.get("consistent", True):
        if args.strict_validation:
            sys.exit(3)
        for msg in val.get("warnings", []):
            print(f"[WARN] {msg}", file=sys.stderr)


if __name__ == "__main__":
    main()
