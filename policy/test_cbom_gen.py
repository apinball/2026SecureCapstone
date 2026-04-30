#!/usr/bin/env python3
"""cbom_gen.py 단위 테스트 — spec_version 별 algorithmFamily 필드 처리."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cbom_gen import (
    TLS13_RFC8446_CIPHER_SUITES,
    build_algorithm_component,
    convert_snapshot_to_cyclonedx,
)


def _alg_props(comp):
    return comp["cryptoProperties"]["algorithmProperties"]


def _custom_props(comp):
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


class TestAlgorithmFamilyNativeField(unittest.TestCase):
    """CycloneDX 1.7 native algorithmFamily 필드는 1.7 에서만 박혀야 한다."""

    def test_17_writes_native_algorithm_family(self):
        _ref, comp = build_algorithm_component(
            "ML-KEM-768", "key-exchange", spec_version="1.7")
        self.assertEqual(_alg_props(comp).get("algorithmFamily"), "ML-KEM")

    def test_17_keeps_custom_property_for_compat(self):
        _ref, comp = build_algorithm_component(
            "ML-KEM-768", "key-exchange", spec_version="1.7")
        self.assertEqual(
            _custom_props(comp).get("securecapstone:algorithmFamily"), "ML-KEM")

    def test_16_does_not_write_native_field(self):
        _ref, comp = build_algorithm_component(
            "ML-KEM-768", "key-exchange", spec_version="1.6")
        self.assertNotIn("algorithmFamily", _alg_props(comp))
        # 커스텀 프로퍼티는 1.6 에서도 그대로 유지 (기존 동작)
        self.assertEqual(
            _custom_props(comp).get("securecapstone:algorithmFamily"), "ML-KEM")

    def test_17_aes(self):
        _ref, comp = build_algorithm_component(
            "AES-256-GCM", "cipher-suite", spec_version="1.7")
        self.assertEqual(_alg_props(comp).get("algorithmFamily"), "AES")

    def test_17_rsa(self):
        # 키 사이즈는 generic-rsa-key-size-weak 룰을 우회하기 위해 3072 사용.
        # 이 테스트는 algorithmFamily 추출만 검증하므로 사이즈는 의미 없음.
        _ref, comp = build_algorithm_component(
            "RSA-3072", "public-key", spec_version="1.7")
        self.assertEqual(_alg_props(comp).get("algorithmFamily"), "RSA")

    def test_curve_remains_custom_only(self):
        """1.7 에서 curve 는 deprecated 됐으므로 커스텀 프로퍼티만 사용."""
        _ref, comp = build_algorithm_component(
            "ECDH-P-256", "key-exchange", spec_version="1.7")
        # algorithmProperties 안에 curve 는 박지 않는다
        self.assertNotIn("curve", _alg_props(comp))
        self.assertEqual(
            _custom_props(comp).get("securecapstone:curve"), "P-256")


def _make_snapshot(*, protocols=None, ciphers=None, neg_cipher=None):
    """TLS 1.3 자동 주입 테스트용 minimal snapshot factory."""
    return {
        "target": {"host": "proxy-server", "port": 443,
                   "stage_requested": "2"},
        "crypto_assets": {
            "configured_protocols": protocols or [],
            "configured_ciphers": ciphers or [],
            "configured_key_exchange": ["X25519MLKEM768"],
            "negotiated_protocol": None,
            "negotiated_cipher": neg_cipher,
            "negotiated_key_exchange": None,
        },
        "analysis_detail": {
            "static": {},
            "dynamic": {"findings": {"certificate": {}}},
        },
    }


def _cipher_components(bom):
    """BOM 에서 cipher-suite 컨텍스트로 등록된 알고리즘 컴포넌트들."""
    out = []
    for c in bom.get("components", []):
        props = c.get("properties") or []
        if any(p["name"] == "securecapstone:cipher_suite" for p in props):
            out.append(c)
    return out


class TestTls13DefaultCipherInjection(unittest.TestCase):
    """TLS 1.3 cipher suite 자동 주입 (RFC 8446 §B.4)."""

    def test_implicit_tls13_injects_rfc8446_ciphers(self):
        """nginx 설정에 cipher 미지정 + protocol TLS 1.3 → 5종 자동 주입."""
        snap = _make_snapshot(protocols=["TLSv1.3"], ciphers=[], neg_cipher=None)
        bom = convert_snapshot_to_cyclonedx(snap)
        cipher_suites = {p["value"] for c in _cipher_components(bom)
                         for p in c.get("properties") or []
                         if p["name"] == "securecapstone:cipher_suite"}
        # RFC 8446 5종이 모두 cipher_suite 프로퍼티 값으로 등록되어야 함
        for suite in TLS13_RFC8446_CIPHER_SUITES:
            self.assertIn(suite, cipher_suites,
                          f"{suite} 가 자동 주입되지 않음")

    def test_implicit_tls13_registers_aes_256_gcm(self):
        """협상 흔히 일어나는 AES-256-GCM 이 BOM 알고리즘으로 등록되어야 한다.

        cbom_diff.verify_tls_against_cbom 이 핸드셰이크 결과 cipher 를
        키워드(예: AES-256-GCM)로 분해해 BOM 에서 찾으므로, 이 알고리즘이
        등록되어 있어야 게이트가 PASS 한다.
        """
        snap = _make_snapshot(protocols=["TLSv1.3"])
        bom = convert_snapshot_to_cyclonedx(snap)
        names = {c["name"] for c in bom["components"]}
        self.assertIn("AES-256-GCM", names)

    def test_explicit_ciphers_skip_injection(self):
        """운영자가 ssl_ciphers 명시한 경우 자동 주입 안 함 (의도 존중)."""
        snap = _make_snapshot(protocols=["TLSv1.3"],
                              ciphers=["TLS_AES_128_GCM_SHA256"])
        bom = convert_snapshot_to_cyclonedx(snap)
        cipher_suites = {p["value"] for c in _cipher_components(bom)
                         for p in c.get("properties") or []
                         if p["name"] == "securecapstone:cipher_suite"}
        # 명시한 한 종만 있어야 함, 자동 5종은 들어가면 안 됨
        self.assertEqual(cipher_suites, {"TLS_AES_128_GCM_SHA256"})

    def test_negotiated_cipher_skip_injection(self):
        """negotiated_cipher 가 있으면 자동 주입 안 함."""
        snap = _make_snapshot(protocols=["TLSv1.3"],
                              neg_cipher="TLS_CHACHA20_POLY1305_SHA256")
        bom = convert_snapshot_to_cyclonedx(snap)
        cipher_suites = {p["value"] for c in _cipher_components(bom)
                         for p in c.get("properties") or []
                         if p["name"] == "securecapstone:cipher_suite"}
        self.assertEqual(cipher_suites, {"TLS_CHACHA20_POLY1305_SHA256"})

    def test_injected_ciphers_have_rfc8446_source_property(self):
        """자동 주입된 컴포넌트는 source=rfc8446-default 로 출처 표시."""
        snap = _make_snapshot(protocols=["TLSv1.3"])
        bom = convert_snapshot_to_cyclonedx(snap)
        for comp in _cipher_components(bom):
            sources = [p["value"] for p in comp.get("properties") or []
                       if p["name"] == "securecapstone:source"]
            self.assertIn("rfc8446-default", sources,
                          f"{comp['name']} 에 rfc8446-default source 없음")

    def test_non_tls13_no_injection(self):
        """TLS 1.2 환경에서는 자동 주입 안 함."""
        snap = _make_snapshot(protocols=["TLSv1.2"])
        bom = convert_snapshot_to_cyclonedx(snap)
        cipher_components = _cipher_components(bom)
        self.assertEqual(cipher_components, [],
                         "TLS 1.2 환경인데 cipher 가 자동 주입됨")

    def test_no_protocols_no_injection(self):
        """protocols 자체가 비어있으면 주입 안 함 (보수적 동작)."""
        snap = _make_snapshot(protocols=[])
        bom = convert_snapshot_to_cyclonedx(snap)
        cipher_components = _cipher_components(bom)
        self.assertEqual(cipher_components, [])


if __name__ == "__main__":
    unittest.main()