# ============================================================
# legacy_crypto_example.py — 고전 암호 사용 예시
#
# PQC 마이그레이션 전 전형적인 고전 암호 패턴을 보여주는 예시 파일입니다.
# 파이프라인의 고전 암호 탐지(Step 5)가 아래 패턴들을 감지하고
# CBOM 리포트에 수동 조치 필요 항목으로 기록합니다.
#
# [탐지 대상]
#   - RSA 키 생성 → ML-KEM (FIPS 203) 으로 교체 필요
#   - MD5 해시    → SHA-256 이상으로 교체 필요
#   - SHA-1 해시  → SHA-256 이상으로 교체 필요
# ============================================================

from Crypto.PublicKey import RSA
import hashlib

# RSA 키 생성 (2048비트) — 양자 컴퓨터에 취약
key = RSA.generate(2048)
public_key = key.publickey().export_key()

# MD5 해시 — 충돌 취약점으로 암호 용도 사용 금지
def hash_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

# SHA-1 해시 — 더 이상 안전하지 않음
def hash_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
