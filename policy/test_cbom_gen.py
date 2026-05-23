#!/usr/bin/env python3
"""cbom_gen.py 단위 테스트 — spec_version 별 algorithmFamily 필드 처리."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cbom_gen import (
    TLS13_RFC8446_CIPHER_SUITES,
    _render_static_notes,
    add_component,
    build_algorithm_component,
    convert_snapshot_to_cyclonedx,
    parse_cert_info,
    resolve_ec_family_from_oid,
    resolve_rsa_family_from_oid,
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

    def test_17_rsa_plain_has_no_spec_family(self):
        # CycloneDX 1.7 cryptography-defs 의 algorithmFamiliesEnum 에는 plain
        # "RSA" 가 없다. RSA 는 사용처(서명/암호화)에 따라 RSAES-OAEP /
        # RSAES-PKCS1 / RSASSA-PKCS1 / RSASSA-PSS 4 개 family 로 세분화된다.
        # `RSA-3072` 같은 표기는 키 길이만 있고 사용처 정보가 없으므로
        # spec 호환되는 family 매핑이 불가능 → family 미설정이 정답.
        # parameterSetIdentifier(=키 길이)는 그대로 추출되어야 한다.
        _ref, comp = build_algorithm_component(
            "RSA-3072", "public-key", spec_version="1.7")
        ap = _alg_props(comp)
        self.assertNotIn("algorithmFamily", ap)
        self.assertEqual(ap.get("parameterSetIdentifier"), "3072")

    def test_17_rsa_signature_oid_maps_to_rsassa_pkcs1(self):
        """cert OID 표기 `sha{N}WithRSAEncryption` → RSASSA-PKCS1 family.

        OpenSSL `x509 -text` 의 Signature Algorithm 으로 흔히 들어오는
        cert 서명 표기. RFC 8017 / RFC 5912 의 RSASSA-PKCS1-v1_5 시그니처
        scheme 에 해당하며, registry 의 pattern
        `RSA-PKCS1-1.5[-{hashAlgorithm}][-{keyLength}]` 와 매핑된다.
        """
        for name in ("sha256WithRSAEncryption", "sha384WithRSAEncryption",
                     "sha512WithRSAEncryption", "sha1WithRSAEncryption"):
            _ref, comp = build_algorithm_component(
                name, "certificate-signature", spec_version="1.7")
            self.assertEqual(_alg_props(comp).get("algorithmFamily"),
                             "RSASSA-PKCS1", f"{name} → RSASSA-PKCS1 expected")

    def test_17_rsassa_pss_explicit(self):
        """`id-RSASSA-PSS` / `rsassa-pss` 표기 → RSASSA-PSS family."""
        _ref, comp = build_algorithm_component(
            "id-RSASSA-PSS", "certificate-signature", spec_version="1.7")
        self.assertEqual(_alg_props(comp).get("algorithmFamily"),
                         "RSASSA-PSS")

    def test_curve_remains_custom_only(self):
        """1.7 에서 curve 는 deprecated 됐으므로 커스텀 프로퍼티만 사용."""
        _ref, comp = build_algorithm_component(
            "ECDH-P-256", "key-exchange", spec_version="1.7")
        # algorithmProperties 안에 curve 는 박지 않는다
        self.assertNotIn("curve", _alg_props(comp))
        self.assertEqual(
            _custom_props(comp).get("securecapstone:curve"), "P-256")


class TestAlgorithmFamilySpecCompliance(unittest.TestCase):
    """CycloneDX 1.7 algorithmFamiliesEnum 호환성.

    1.6 시절에는 algorithmFamily 가 native 필드가 아니어서 임의 값이
    허용됐으나, 1.7 부터는 enum 검증 대상이 되어 spec 호환 값이 필수.
    SHA family 분리 (SHA-1/SHA-2/SHA-3) 와 ChaCha20-Poly1305 → ChaCha20
    정규화 동작을 검증한다.
    """

    def _family(self, name, ctx="cipher-suite"):
        _, comp = build_algorithm_component(name, ctx, spec_version="1.7")
        return _alg_props(comp).get("algorithmFamily")

    def test_sha2_family_for_sha224_256_384_512(self):
        """SHA-224/256/384/512 → SHA-2 (FIPS 180-4 family)."""
        for name in ("SHA224", "SHA256", "SHA384", "SHA512",
                     "SHA-224", "SHA-256", "SHA-384", "SHA-512"):
            self.assertEqual(self._family(name), "SHA-2",
                             f"{name} → SHA-2 expected")

    def test_sha1_family_only_for_sha1(self):
        """SHA1 / SHA-1 만 SHA-1 (FIPS 180-4)."""
        self.assertEqual(self._family("SHA1"), "SHA-1")
        self.assertEqual(self._family("SHA-1"), "SHA-1")
        self.assertEqual(self._family("sha1"), "SHA-1")

    def test_sha3_family_for_sha3_and_extensions(self):
        """SHA3-*, SHAKE*, cSHAKE*, KMAC* → SHA-3 (FIPS 202)."""
        for name in ("SHA3-256", "SHAKE128", "cSHAKE256",
                     "KMAC128", "TupleHash256"):
            self.assertEqual(self._family(name), "SHA-3",
                             f"{name} → SHA-3 expected")

    def test_sha384_not_misclassified_as_sha3(self):
        """회귀 방지: SHA384 가 'sha3' 부분 매칭으로 SHA-3 가 되면 안 됨."""
        self.assertEqual(self._family("SHA384"), "SHA-2")
        self.assertEqual(self._family("SHA-384"), "SHA-2")

    def test_chacha20_poly1305_normalizes_to_chacha20(self):
        """CycloneDX 1.7 enum 에 ChaCha20-Poly1305 family 는 없음.
        ChaCha20 family 안에 ChaCha20-Poly1305 (ae) 변형이 정의됨."""
        self.assertEqual(self._family("ChaCha20-Poly1305"), "ChaCha20")
        self.assertEqual(self._family("ChaCha20"), "ChaCha20")

    def test_all_native_families_are_in_spec_enum(self):
        """TLS 1.3 자동 주입 결과 BOM 의 모든 algorithmFamily 가 spec enum 에 부합해야 한다.

        스키마 validation 실패가 가장 자주 나는 경로 (Step 11 schema check) 의
        회귀 가드. CycloneDX 1.7 의 algorithmFamiliesEnum 은 별도 sub-schema
        `cryptography-defs.schema.json` 의 정식 family 목록을 따른다.
        https://cyclonedx.org/registry/cryptography/ 에서 확인 가능.

        주의: plain "RSA" / "DH" / "GMAC" / "Camellia" 등은 1.7 registry 에
        존재하지 않는다 (이전 9주차 set 에 잘못 박혀있던 항목). RSA 는
        RSAES-OAEP / RSAES-PKCS1 / RSASSA-PKCS1 / RSASSA-PSS 로만 표현되며,
        DH 는 FFDH / ECDH / MQV 등으로 세분화, Camellia 는 spec 표기 CAMELLIA,
        GMAC 은 AES family 안의 패턴이라 family 명칭이 아니다.
        """
        spec_allowed = {
            # 대칭암호
            "AES", "CAMELLIA", "Twofish", "Serpent", "ARIA", "SEED",
            "3DES", "DES", "Blowfish", "RC2", "RC4", "RC5", "RC6",
            "ChaCha20", "ChaCha", "Salsa20",
            # MAC
            "HMAC", "CMAC", "Poly1305", "UMAC", "SipHash",
            # 해시
            "SHA-1", "SHA-2", "SHA-3", "MD5", "MD4", "MD2",
            "BLAKE2", "BLAKE3", "RIPEMD", "Whirlpool",
            # 전통 비대칭
            "DSA", "ECDSA", "EdDSA",
            "RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PKCS1", "RSASSA-PSS",
            # 키 합의
            "ECDH", "FFDH", "MQV", "X3DH",
            "SPAKE2", "SPAKE2PLUS", "SRP", "J-PAKE", "OPAQUE", "HPKE",
            # PQC
            "ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS",
            # KDF
            "PBKDF2", "PBKDF1", "HKDF", "Argon2", "scrypt", "bcrypt",
            "yescrypt", "ANSI-KDF", "TLS-PRF", "SP800-108", "SP800-56C",
            # 기타
            "ECIES", "ElGamal", "BLS", "Ascon",
            "PBES1", "PBES2", "PBMAC1",
            "SM2", "SM3", "SM4", "SM9", "GOST",
        }
        # TLS 1.3 자동 주입 시나리오
        snap = _make_snapshot(protocols=["TLSv1.3"])
        bom = convert_snapshot_to_cyclonedx(snap)
        for comp in bom["components"]:
            ap = comp.get("cryptoProperties", {}).get("algorithmProperties", {})
            family = ap.get("algorithmFamily")
            if family is None:
                continue
            self.assertIn(family, spec_allowed,
                          f"{comp['name']} 의 algorithmFamily='{family}' 가 "
                          f"CycloneDX 1.7 cryptography-defs 에 없음")


class TestPqcSignatureFamilyMapping(unittest.TestCase):
    """PQC 시그니처 family 매핑 (CycloneDX 1.7 cryptography-defs).

    9주차 SHA / ChaCha20 정규화의 후속. PQC 시그니처 이름에 포함된 SHA 부분
    문자열이 SHA family 로 잘못 매칭되던 회귀를 차단하고, ML-DSA / SLH-DSA
    family 를 spec 호환 값으로 박는다.
    """

    def _family(self, name, ctx="cipher-suite"):
        _, comp = build_algorithm_component(name, ctx, spec_version="1.7")
        return _alg_props(comp).get("algorithmFamily")

    def test_slh_dsa_sha2_not_misclassified_as_sha2(self):
        """`SLH-DSA-SHA2-128s` 같은 이름이 'sha2' 부분 매칭으로 SHA-2 family
        가 되던 회귀 차단 (가장 큰 결함이었음)."""
        for name in ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
                     "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
                     "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"):
            self.assertEqual(self._family(name), "SLH-DSA",
                             f"{name} 가 SHA family 로 오분류됨")

    def test_slh_dsa_shake_not_misclassified_as_sha3(self):
        """SLH-DSA SHAKE 변종도 'shake' 부분 매칭으로 SHA-3 가 되면 안 됨."""
        for name in ("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
                     "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-256s"):
            self.assertEqual(self._family(name), "SLH-DSA",
                             f"{name} 가 SHA-3 로 오분류됨")

    def test_sphincs_plus_aliases_to_slh_dsa(self):
        """SPHINCS+ 는 FIPS 표준화 이전의 옛 이름. SLH-DSA family alias 로
        처리해 표기 다양성에 대해 일관된 family 값을 보장한다."""
        for name in ("SPHINCS+-SHA2-128s", "SPHINCS+-SHAKE-128s",
                     "sphincsplus-sha2-256s"):
            self.assertEqual(self._family(name), "SLH-DSA",
                             f"{name} 가 SLH-DSA 로 매핑되지 않음")

    def test_ml_dsa_family(self):
        for name in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
            self.assertEqual(self._family(name), "ML-DSA")

    def test_dilithium_aliases_to_ml_dsa(self):
        """Dilithium 은 FIPS 204 표준화 전 이름. ML-DSA family alias."""
        for name in ("Dilithium2", "Dilithium3", "Dilithium5", "dilithium2"):
            self.assertEqual(self._family(name), "ML-DSA")

    def test_falcon_no_family_registry_pending(self):
        """Falcon (FN-DSA) 은 CycloneDX 1.7 registry 미등재 상태.
        family 매핑 불가가 정답 — registry 추가 시 매핑 추가 검토."""
        self.assertIsNone(self._family("Falcon-512"))
        self.assertIsNone(self._family("Falcon-1024"))


class TestEddsaEcdhFamilyMapping(unittest.TestCase):
    """EdDSA / ECDH family 매핑 보강."""

    def _family(self, name, ctx="cipher-suite"):
        _, comp = build_algorithm_component(name, ctx, spec_version="1.7")
        return _alg_props(comp).get("algorithmFamily")

    def test_ed25519_ed448_to_eddsa(self):
        for name in ("Ed25519", "Ed448", "ed25519", "ED25519"):
            self.assertEqual(self._family(name), "EdDSA",
                             f"{name} → EdDSA expected")

    def test_ecdhe_normalized_to_ecdh(self):
        """ECDHE 는 ephemeral ECDH 의 통칭이며 registry pattern
        `ECDH[E][-{ellipticCurve}]` 안에 정의되어 있다. family 는 ECDH."""
        self.assertEqual(self._family("ECDHE"), "ECDH")
        self.assertEqual(self._family("ECDH-P-256"), "ECDH")

    def test_ecdsa_not_confused_with_ecdh(self):
        """word-boundary 회귀 가드 — 'ecdsa' 안의 'ecd' 가 ECDH 로 잘못
        매칭되거나 그 역이 발생하지 않아야 한다."""
        self.assertEqual(self._family("ECDSA"), "ECDSA")
        self.assertEqual(self._family("ecdsa-with-SHA256"), "ECDSA")

    def test_x25519_x448_to_ecdh(self):
        """RFC 7748 Montgomery curve DH (X25519/X448) 는 CycloneDX 1.7
        registry 상 ECDH family 에 속한다. 단독 표기 매칭 회귀 가드."""
        for name in ("X25519", "x25519", "X448", "x448"):
            self.assertEqual(self._family(name), "ECDH",
                             f"{name} → ECDH expected")

    def test_x25519_hybrid_stays_mlkem(self):
        """X25519MLKEM768 같은 PQC 하이브리드는 family 가 ML-KEM 으로
        먼저 박힌다 — ECDH 매핑이 이를 덮어쓰지 않아야 한다."""
        self.assertEqual(self._family("X25519MLKEM768"), "ML-KEM")


class TestPrimitiveCryptoFunctionsConsistency(unittest.TestCase):
    """primitive 와 cryptoFunctions 의 의미론적 일관성 회귀 가드.

    하이브리드 KEM combiner (X25519MLKEM768 등) 가 KEM 함수 집합을 갖지
    못해 downstream 정책 게이트(`cryptoFunctions contains "encapsulate"`
    로 PQC KEM 식별) 가 PQC 컴포넌트를 놓치는 회귀를 차단한다.
    """

    def _build(self, name, ctx="key-exchange"):
        _ref, comp = build_algorithm_component(name, ctx, spec_version="1.7")
        return comp

    def test_hybrid_combiner_includes_kem_functions(self):
        """X25519MLKEM768 (draft-kwiatkowski-tls-ecdhe-mlkem) 는 PQC KEM 과
        고전 ECDH 를 합치는 combiner. cryptoFunctions 에 encapsulate/
        decapsulate 가 반드시 포함되어야 한다."""
        comp = self._build("X25519MLKEM768")
        ap = _alg_props(comp)
        self.assertEqual(ap.get("primitive"), "combiner")
        self.assertIn("encapsulate", ap.get("cryptoFunctions", []))
        self.assertIn("decapsulate", ap.get("cryptoFunctions", []))

    def test_pure_kem_functions_are_encap_decap(self):
        """순수 ML-KEM 의 primitive=kem 은 encap/decap 만 가진다."""
        comp = self._build("ML-KEM-768")
        ap = _alg_props(comp)
        self.assertEqual(ap.get("primitive"), "kem")
        self.assertEqual(set(ap.get("cryptoFunctions", [])),
                         {"encapsulate", "decapsulate"})

    def test_classical_key_agree_functions(self):
        """고전 키교환 (X25519/ECDH) 는 keygen/keyderive."""
        for name in ("X25519", "ECDH-P-256"):
            ap = _alg_props(self._build(name))
            self.assertEqual(ap.get("primitive"), "key-agree", name)
            self.assertEqual(set(ap.get("cryptoFunctions", [])),
                             {"keygen", "keyderive"}, name)

    def test_x448_primitive_is_key_agree(self):
        """X448 (RFC 7748) 단독 표기도 primitive=key-agree 로 박혀야 한다.
        과거 분기가 'x25519' 만 보고 X448 을 흘려보내던 회귀."""
        ap = _alg_props(self._build("X448"))
        self.assertEqual(ap.get("primitive"), "key-agree")


class TestRsaOidResolver(unittest.TestCase):
    """RSA OID/이름 → CycloneDX 1.7 family 매핑.

    사용처(KeyUsage) 무관 OID 는 즉시 family 단정, ambiguous OID
    (rsaEncryption) 는 KeyUsage 비트로 분기한다.
    """

    def test_signature_oids_map_to_rsassa_pkcs1(self):
        cases = [
            "1.2.840.113549.1.1.11",       # sha256WithRSAEncryption
            "1.2.840.113549.1.1.12",       # sha384WithRSAEncryption
            "1.2.840.113549.1.1.13",       # sha512WithRSAEncryption
            "1.2.840.113549.1.1.5",        # sha1WithRSAEncryption
            "sha256WithRSAEncryption",
            "sha512WithRSAEncryption",
        ]
        for name in cases:
            self.assertEqual(resolve_rsa_family_from_oid(name, None),
                             "RSASSA-PKCS1", name)

    def test_pss_oid_maps_to_rsassa_pss(self):
        for name in ("1.2.840.113549.1.1.10", "id-RSASSA-PSS", "rsassa-pss"):
            self.assertEqual(resolve_rsa_family_from_oid(name, None),
                             "RSASSA-PSS", name)

    def test_oaep_oid_maps_to_rsaes_oaep(self):
        for name in ("1.2.840.113549.1.1.7", "id-RSAES-OAEP", "rsaes-oaep"):
            self.assertEqual(resolve_rsa_family_from_oid(name, None),
                             "RSAES-OAEP", name)

    def test_rsa_encryption_with_digital_signature_keyusage(self):
        """rsaEncryption + KeyUsage:digitalSignature → RSASSA-PKCS1.
        modern TLS 1.2/1.3 RSA 서버 인증서의 dominant pattern."""
        self.assertEqual(
            resolve_rsa_family_from_oid(
                "rsaEncryption", ["digital_signature"]),
            "RSASSA-PKCS1")
        self.assertEqual(
            resolve_rsa_family_from_oid(
                "1.2.840.113549.1.1.1", ["digital_signature"]),
            "RSASSA-PKCS1")

    def test_rsa_encryption_with_key_encipherment_keyusage(self):
        """rsaEncryption + KeyUsage:keyEncipherment → RSAES-PKCS1.
        TLS_RSA 키 전송 패턴 (TLS 1.3 에서는 제거됐지만 1.2 잔존)."""
        self.assertEqual(
            resolve_rsa_family_from_oid(
                "rsaEncryption", ["key_encipherment"]),
            "RSAES-PKCS1")

    def test_rsa_encryption_without_keyusage_remains_ambiguous(self):
        """KeyUsage 없으면 단정 불가 → None 반환. CycloneDX 1.7 spec
        의 RSA family 가 강제하는 정직한 미상태."""
        self.assertIsNone(resolve_rsa_family_from_oid("rsaEncryption", None))
        self.assertIsNone(resolve_rsa_family_from_oid("rsaEncryption", []))

    def test_signature_priority_when_both_keyusages_set(self):
        """digitalSignature + keyEncipherment 둘 다 박힌 경우 — 현대 TLS
        의 dominant usage 인 서명 우선 (RSASSA-PKCS1)."""
        family = resolve_rsa_family_from_oid(
            "rsaEncryption",
            ["digital_signature", "key_encipherment"])
        self.assertEqual(family, "RSASSA-PKCS1")

    def test_rsa_key_length_name_not_resolved(self):
        """`RSA-3072` 같은 키 길이 표기는 OID 가 아니므로 None.
        family 단정 불가 — parameterSetIdentifier 만 추출되는 기존 동작 유지."""
        self.assertIsNone(resolve_rsa_family_from_oid("RSA-3072", None))


class TestEcOidResolver(unittest.TestCase):
    """id-ecPublicKey + KeyUsage → ECDSA / ECDH 분기."""

    def test_ec_public_key_with_digital_signature(self):
        self.assertEqual(
            resolve_ec_family_from_oid(
                "id-ecPublicKey", ["digital_signature"]),
            "ECDSA")
        self.assertEqual(
            resolve_ec_family_from_oid(
                "1.2.840.10045.2.1", ["digital_signature"]),
            "ECDSA")

    def test_ec_public_key_with_key_agreement(self):
        self.assertEqual(
            resolve_ec_family_from_oid(
                "id-ecPublicKey", ["key_agreement"]),
            "ECDH")

    def test_ec_public_key_without_keyusage(self):
        self.assertIsNone(
            resolve_ec_family_from_oid("id-ecPublicKey", None))

    def test_ecdsa_oid_not_in_ec_resolver(self):
        """ecdsa-with-* 표기는 EC ambiguous 가 아님 — 기존 패턴 분기가 처리.
        EC OID resolver 는 None 반환이 정답."""
        self.assertIsNone(
            resolve_ec_family_from_oid(
                "ecdsa-with-SHA256", ["digital_signature"]))


class TestPublicKeyContextWithKeyUsage(unittest.TestCase):
    """build_algorithm_component(context='public-key', key_usage=...) 통합 검증."""

    def _build(self, name, key_usage):
        _ref, comp = build_algorithm_component(
            name, "public-key", spec_version="1.7", key_usage=key_usage)
        return _alg_props(comp)

    def test_rsa_signing_cert_public_key(self):
        ap = self._build("rsaEncryption", ["digital_signature"])
        self.assertEqual(ap.get("algorithmFamily"), "RSASSA-PKCS1")
        self.assertEqual(ap.get("primitive"), "signature")
        self.assertEqual(ap.get("cryptoFunctions"), ["verify"])

    def test_rsa_encipherment_cert_public_key(self):
        ap = self._build("rsaEncryption", ["key_encipherment"])
        self.assertEqual(ap.get("algorithmFamily"), "RSAES-PKCS1")
        self.assertEqual(ap.get("primitive"), "pke")
        # 공개키가 대칭키를 encrypt — verify 아님.
        self.assertEqual(ap.get("cryptoFunctions"), ["encrypt"])

    def test_ec_signing_cert_public_key(self):
        ap = self._build("id-ecPublicKey", ["digital_signature"])
        self.assertEqual(ap.get("algorithmFamily"), "ECDSA")
        self.assertEqual(ap.get("primitive"), "signature")
        self.assertEqual(ap.get("cryptoFunctions"), ["verify"])

    def test_ec_keyagreement_cert_public_key(self):
        ap = self._build("id-ecPublicKey", ["key_agreement"])
        self.assertEqual(ap.get("algorithmFamily"), "ECDH")
        self.assertEqual(ap.get("primitive"), "key-agree")
        self.assertEqual(ap.get("cryptoFunctions"), ["keyderive"])

    def test_rsa_public_key_without_usage_still_no_family(self):
        """KeyUsage 가 없으면 family 미설정. 기존 보수적 동작 유지."""
        ap = self._build("rsaEncryption", None)
        self.assertNotIn("algorithmFamily", ap)


class TestParseCertInfoKeyUsage(unittest.TestCase):
    """parse_cert_info — openssl x509 -text 출력에서 X509v3 Key Usage 파싱."""

    def test_parses_digital_signature_and_key_encipherment(self):
        cert_text = (
            "Public Key Algorithm: rsaEncryption\n"
            "    Public-Key: (3072 bit)\n"
            "X509v3 Key Usage: critical\n"
            "    Digital Signature, Key Encipherment\n"
        )
        result = parse_cert_info(cert_text)
        self.assertEqual(
            result.get("key_usage"),
            ["digital_signature", "key_encipherment"])

    def test_parses_single_usage_bit(self):
        cert_text = (
            "Public Key Algorithm: id-ecPublicKey\n"
            "X509v3 Key Usage: \n"
            "    Digital Signature\n"
        )
        result = parse_cert_info(cert_text)
        self.assertEqual(result.get("key_usage"), ["digital_signature"])

    def test_absent_key_usage_omitted(self):
        cert_text = (
            "Public Key Algorithm: rsaEncryption\n"
            "    Public-Key: (2048 bit)\n"
        )
        result = parse_cert_info(cert_text)
        self.assertNotIn("key_usage", result)

    def test_parses_wrapped_multiline_key_usage(self):
        """openssl 또는 다른 도구가 KU 비트 다수를 80-col wrap 한 경우.
        과거 정규식 `[^\\n]+` 가 첫 줄에서 끊겨 후속 비트가 누락되던 회귀 가드.
        CA cert 가 8비트 다 박혀있을 때 흔히 발생."""
        cert_text = (
            "X509v3 Key Usage: critical\n"
            "    Digital Signature, Non Repudiation, Key Encipherment, Data\n"
            "    Encipherment, Key Agreement, Certificate Sign, CRL Sign\n"
            "X509v3 Subject Key Identifier:\n"
            "    AB:CD:EF\n"
        )
        result = parse_cert_info(cert_text)
        usages = result.get("key_usage", [])
        # 7개 KU 비트 전부 + 'data_encipherment' 가 안 잘리고 정상 결합되어야 함
        self.assertIn("digital_signature", usages)
        self.assertIn("non_repudiation", usages)
        self.assertIn("key_encipherment", usages)
        self.assertIn("data_encipherment", usages)
        self.assertIn("key_agreement", usages)
        self.assertIn("certificate_sign", usages)
        self.assertIn("crl_sign", usages)
        # 잘린 'data' 토큰이 들어가면 안 됨
        self.assertNotIn("data", usages)

    def test_does_not_overcapture_next_x509v3_extension(self):
        """실제 openssl x509 -text 출력은 extension 헤더를 col 12 (X509v3
        extensions: 안쪽) 들여쓰기로 박는다. 헤더와 컨텐츠가 둘 다 들여쓰기
        되어있어 과거 정규식이 후속 extension 의 컨텐츠까지 빨아먹어
        `key_encipherment_x509v3_subject_key_identifier:_ab:cd:...` 같은
        garbage 토큰을 만들었다. 결과적으로 OID resolver 의 KeyUsage lookup
        이 silent 실패 (key_encipherment 비트 손실 → RSAES family 미식별)."""
        cert_text = (
            "        X509v3 extensions:\n"
            "            X509v3 Key Usage: critical\n"
            "                Digital Signature, Key Encipherment\n"
            "            X509v3 Subject Key Identifier:\n"
            "                AB:CD:EF:01:23:45\n"
            "            X509v3 Extended Key Usage:\n"
            "                TLS Web Server Authentication\n"
        )
        result = parse_cert_info(cert_text)
        usages = result.get("key_usage", [])
        # 정확히 2개만 박혀야 함. 후속 extension 의 컨텐츠 누출 금지.
        self.assertEqual(sorted(usages),
                         sorted(["digital_signature", "key_encipherment"]),
                         f"over-capture detected: {usages}")


class TestAddComponentDedupe(unittest.TestCase):
    """동일 ref 두 번 등록 (configured + negotiated 양쪽 잡힘) 시 list
    필드 중복 누적 방지 회귀 가드. CBOM diff 노이즈 차단."""

    def test_crypto_functions_no_dup_on_double_register(self):
        ref, comp = build_algorithm_component(
            "X25519MLKEM768", "key-exchange", spec_version="1.7")
        registry = {}
        add_component(registry, comp)
        # 같은 컴포넌트 한 번 더 등록 — configured/negotiated 양쪽 잡히는 정상 경로
        _ref2, comp2 = build_algorithm_component(
            "X25519MLKEM768", "key-exchange", spec_version="1.7")
        add_component(registry, comp2)
        cf = registry[ref]["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"]
        self.assertEqual(len(cf), len(set(cf)),
                         f"cryptoFunctions 중복 누적: {cf}")

    def test_properties_no_dup_on_double_register(self):
        ref, comp = build_algorithm_component(
            "X25519MLKEM768", "key-exchange", spec_version="1.7")
        registry = {}
        add_component(registry, comp)
        add_component(registry, dict(comp))  # 동일 component 재등록
        seen = set()
        for p in registry[ref].get("properties", []):
            key = (p.get("name"), p.get("value"))
            self.assertNotIn(key, seen, f"properties 중복: {p}")
            seen.add(key)

    def test_cross_context_collision_unions_crypto_functions(self):
        """동일 알고리즘 이름이 두 context 로 들어왔을 때 — 현재 bom-ref 가
        `crypto/algorithm/<slug>` 라 context 가 ref 에 안 포함되므로 같은
        엔트리로 머지된다. 이때 cryptoFunctions 는 두 context 의 union 이
        되는 것이 현재 동작 (의도된 약점).

        이 동작이 미래에 바뀐다면 (예: bom-ref 에 context 포함) 이 테스트가
        깨지면서 의식적인 변경을 요구함. 그때까지는 union 으로 두되, 실환경
        트리거 케이스가 없음을 회귀 테스트로 보존."""
        # ECDSA 가 cipher-suite 추출 결과 standalone + cert-signature 양쪽
        # 컨텍스트로 들어오는 가상 시나리오.
        ref1, comp1 = build_algorithm_component(
            "ECDSA", "cipher-suite", spec_version="1.7")
        ref2, comp2 = build_algorithm_component(
            "ECDSA", "certificate-signature", spec_version="1.7")
        self.assertEqual(ref1, ref2, "현재 ref 는 context 미포함")
        registry = {}
        add_component(registry, comp1)
        add_component(registry, comp2)
        # cert-signature 에서 박힌 sign/verify 가 살아있어야 함
        cf = registry[ref1]["cryptoProperties"]["algorithmProperties"].get(
            "cryptoFunctions", [])
        self.assertIn("sign", cf)
        self.assertIn("verify", cf)


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


class TestStaticNotesRedact(unittest.TestCase):
    """notes:static 에 cert/key 경로 PII 가 redact=True 일 때 누출되지 않아야 한다.

    과거엔 notes:static 이 BOM emit 시 redact 와 무관하게 raw 경로를 박은
    문자열 그대로 통과했음. config_mismatch 구조화 note 도입 후 emit 시점에
    path-bearing key 의 값을 정제하도록 변경."""

    def _path_mismatch_record(self, key, lv, cv):
        return {"kind": "config_mismatch", "key": key,
                "local_value": lv, "container_value": cv}

    def test_path_key_redacted_when_redact_true(self):
        rec = self._path_mismatch_record(
            "ssl_certificate",
            "/etc/nginx/certs/server.crt",
            "/opt/secrets/prod-leaf.pem")
        rendered = _render_static_notes([rec], redact=True)
        joined = " ".join(rendered)
        # raw path 가 BOM 에 들어가면 안 됨
        self.assertNotIn("/etc/nginx/certs/server.crt", joined)
        self.assertNotIn("/opt/secrets/prod-leaf.pem", joined)
        # 정제된 값은 들어가야 함 (config mismatch 신호 자체는 유지)
        self.assertIn("redacted-", joined)
        # 키 이름 자체는 PII 아니므로 유지
        self.assertIn("ssl_certificate", joined)

    def test_path_key_visible_when_redact_false(self):
        rec = self._path_mismatch_record(
            "ssl_certificate_key",
            "/etc/nginx/server.key",
            "/opt/secrets/prod.key")
        rendered = _render_static_notes([rec], redact=False)
        joined = " ".join(rendered)
        self.assertIn("/etc/nginx/server.key", joined)
        self.assertIn("/opt/secrets/prod.key", joined)

    def test_non_path_key_not_redacted_either_mode(self):
        """ssl_protocols 같은 비-경로 키는 redact 와 무관하게 그대로 노출.
        리스트 형태 값이 raw repr 로 들어가도 PII 우려 없음."""
        rec = self._path_mismatch_record(
            "ssl_protocols", ["TLSv1.3"], ["TLSv1.2", "TLSv1.3"])
        for redact in (True, False):
            rendered = _render_static_notes([rec], redact=redact)
            joined = " ".join(rendered)
            self.assertIn("TLSv1.3", joined, f"redact={redact}")
            self.assertNotIn("redacted-", joined,
                             f"비-경로 키가 정제되면 안 됨 (redact={redact})")

    def test_plain_string_notes_pass_through(self):
        """기존 plain string note (PII 없는 분석 메시지) 는 redact 무관 통과."""
        msg = "TLS 1.3 전용 설정으로 ssl_ciphers 미지정 (정상)."
        for redact in (True, False):
            rendered = _render_static_notes([msg], redact=redact)
            self.assertEqual(rendered, [msg])

    def test_mixed_list_handled(self):
        notes = [
            "plain 분석 note",
            self._path_mismatch_record(
                "ssl_certificate", "/x/y.crt", "/a/b.crt"),
            "another plain note",
        ]
        rendered = _render_static_notes(notes, redact=True)
        self.assertEqual(len(rendered), 3)
        self.assertEqual(rendered[0], "plain 분석 note")
        self.assertIn("redacted-", rendered[1])
        self.assertNotIn("/x/y.crt", rendered[1])
        self.assertEqual(rendered[2], "another plain note")


if __name__ == "__main__":
    unittest.main()