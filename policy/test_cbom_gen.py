#!/usr/bin/env python3
"""cbom_gen.py 단위 테스트 — spec_version 별 algorithmFamily 필드 처리."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cbom_gen import build_algorithm_component


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
        _ref, comp = build_algorithm_component(
            "RSA-2048", "public-key", spec_version="1.7")
        self.assertEqual(_alg_props(comp).get("algorithmFamily"), "RSA")

    def test_curve_remains_custom_only(self):
        """1.7 에서 curve 는 deprecated 됐으므로 커스텀 프로퍼티만 사용."""
        _ref, comp = build_algorithm_component(
            "ECDH-P-256", "key-exchange", spec_version="1.7")
        # algorithmProperties 안에 curve 는 박지 않는다
        self.assertNotIn("curve", _alg_props(comp))
        self.assertEqual(
            _custom_props(comp).get("securecapstone:curve"), "P-256")


if __name__ == "__main__":
    unittest.main()
