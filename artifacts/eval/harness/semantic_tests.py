"""Semantic test cases — 마이그레이션 결과 모듈을 import해 실제로 실행 후 의도한 동작 확인.

각 패턴마다 (1) 정답 모듈로 입출력이 통과하는 것을 보장하는 baseline test와
(2) LLM 출력 모듈에 같은 test를 적용. 통과 여부가 L3 지표.

NOTE: oqs(liboqs-python) 설치가 필요. 미설치 시 SkipTest.
"""
import importlib.util
import os
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class TestResult:
    pattern_id: str
    passed: bool
    error: str | None = None
    details: dict = field(default_factory=dict)


def load_module(source_path: Path, module_name: str) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, source_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {source_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# ──────────────────────────────────────────────────────────────────────
# Pattern-specific test cases
# 각 함수 시그니처: (module) -> bool (raises on failure)
# ──────────────────────────────────────────────────────────────────────

def test_01_keygen_simple(m: Any) -> None:
    result = m.generate_keypair()
    if not isinstance(result, tuple) or len(result) != 2:
        raise AssertionError("generate_keypair must return a 2-tuple")
    obj, public_key = result
    if not isinstance(public_key, (bytes, bytearray)):
        raise AssertionError(f"public_key should be bytes, got {type(public_key)}")
    if len(public_key) < 100:
        raise AssertionError(f"public_key length {len(public_key)} too small for ML-KEM")


def test_02_encrypt_simple(m: Any) -> None:
    """encrypt(pub, msg) → ciphertext. decrypt(kem, ct) == msg."""
    keygen_mod = _load_reference("01_cryptography_keygen_simple")
    kem, public_key = keygen_mod.generate_keypair()
    msg = b"hello PQC"
    ct = m.encrypt_message(public_key, msg)
    if not isinstance(ct, (bytes, bytearray)):
        raise AssertionError("ciphertext should be bytes")
    pt = m.decrypt_message(kem, ct)
    if pt != msg:
        raise AssertionError(f"roundtrip mismatch: {pt!r} != {msg!r}")


def test_03_sign_simple(m: Any) -> None:
    import oqs
    signer = oqs.Signature("ML-DSA-65")
    public_key = signer.generate_keypair()
    msg = b"document to sign"
    sig = m.sign(signer, msg)
    if not m.verify(public_key, msg, sig):
        raise AssertionError("verify failed on valid signature")
    if m.verify(public_key, b"tampered", sig):
        raise AssertionError("verify accepted tampered message")


def test_04_kex_simple(m: Any) -> None:
    keygen_mod = _load_reference("01_cryptography_keygen_simple")
    kem, public_key = keygen_mod.generate_keypair()
    msg = b"session payload"
    wrapped, nonce, ct = m.wrap_and_encrypt(public_key, msg)
    pt = m.unwrap_and_decrypt(kem, wrapped, nonce, ct)
    if pt != msg:
        raise AssertionError("KEX roundtrip mismatch")


def test_05_keygen_complex(m: Any) -> None:
    with tempfile.TemporaryDirectory() as d:
        km = m.KeyManager(Path(d))
        km.generate()
        km.save("test")
        km2 = m.KeyManager(Path(d))
        km2.load("test")
        # 동일 KEM 인스턴스 흐름으로 encap/decap 가능한지
        import oqs
        with oqs.KeyEncapsulation(getattr(km2, "KEM_ALG", "ML-KEM-768")) as kem:
            ct, ss = kem.encap_secret(km2.public_key)
        ss2 = km2.kem.decap_secret(ct)
        if ss != ss2:
            raise AssertionError("loaded key produces different shared secret")


def test_06_encrypt_complex(m: Any) -> None:
    keygen_mod = _load_reference("05_cryptography_keygen_complex")
    with tempfile.TemporaryDirectory() as d:
        km = keygen_mod.KeyManager(Path(d))
        km.generate()
        km.save("k")
        msg_path = Path(d) / "msg.txt"
        ct_path = Path(d) / "ct.bin"
        out_path = Path(d) / "out.txt"
        msg_path.write_bytes(b"complex encrypt")
        sender = m.SecureMessenger(public_key_path=Path(d) / "k.pub.bin")
        sender.encrypt_file(msg_path, ct_path)
        receiver = m.SecureMessenger(private_key_path=Path(d) / "k.priv.bin")
        receiver.decrypt_file(ct_path, out_path)
        if out_path.read_bytes() != b"complex encrypt":
            raise AssertionError("file encrypt roundtrip mismatch")


def test_07_sign_complex(m: Any) -> None:
    import oqs
    with tempfile.TemporaryDirectory() as d:
        signer = oqs.Signature("ML-DSA-65")
        pub = signer.generate_keypair()
        secret = signer.export_secret_key()
        priv_path = Path(d) / "k.priv.bin"
        pub_path = Path(d) / "k.pub.bin"
        priv_path.write_bytes(secret)
        pub_path.write_bytes(pub)
        doc = Path(d) / "doc.txt"
        sig = Path(d) / "doc.sig"
        doc.write_bytes(b"contract")
        s = m.DocumentSigner(private_key_path=priv_path, public_key_path=pub_path)
        s.sign_file(doc, sig)
        if not s.verify_file(doc, sig):
            raise AssertionError("verify_file failed on valid signature")


def test_08_kex_complex(m: Any) -> None:
    keygen_mod = _load_reference("05_cryptography_keygen_complex")
    with tempfile.TemporaryDirectory() as d:
        km = keygen_mod.KeyManager(Path(d))
        km.generate()
        km.save("bob")
        wrapped = Path(d) / "wrapped.bin"
        alice = m.SessionKeyExchange(peer_pub_path=Path(d) / "bob.pub.bin")
        sk_alice = alice.initiate(wrapped)
        bob = m.SessionKeyExchange(my_priv_path=Path(d) / "bob.priv.bin")
        sk_bob = bob.respond(wrapped)
        if sk_alice != sk_bob:
            raise AssertionError("session keys differ")


def test_09_sign_simple_pyc(m: Any) -> None:
    import oqs
    signer = oqs.Signature("ML-DSA-65")
    public_key = signer.generate_keypair()
    msg = b"sign me"
    sig = m.sign(signer, msg)
    if not m.verify(public_key, msg, sig):
        raise AssertionError("verify failed")


def test_10_keygen_simple_pyc(m: Any) -> None:
    result = m.generate_keypair()
    if not isinstance(result, tuple) or len(result) != 2:
        raise AssertionError("must return 2-tuple")
    _, public_key = result
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) < 100:
        raise AssertionError("public_key invalid")


def test_11_encrypt_simple_pyc(m: Any) -> None:
    keygen_mod = _load_reference("10_pycryptodome_keygen_simple")
    kem, pub = keygen_mod.generate_keypair()
    msg = b"hi"
    ct = m.encrypt_message(pub, msg)
    pt = m.decrypt_message(kem, ct)
    if pt != msg:
        raise AssertionError("roundtrip mismatch")


def test_12_kex_simple_pyc(m: Any) -> None:
    keygen_mod = _load_reference("10_pycryptodome_keygen_simple")
    kem, pub = keygen_mod.generate_keypair()
    msg = b"payload"
    wrapped, nonce, tag, ct = m.wrap_and_encrypt(pub, msg)
    pt = m.unwrap_and_decrypt(kem, wrapped, nonce, tag, ct)
    if pt != msg:
        raise AssertionError("KEX roundtrip mismatch")


def test_13_keygen_complex_pyc(m: Any) -> None:
    with tempfile.TemporaryDirectory() as d:
        os.environ["KEY_DIR"] = d
        kv = m.KeyVault()
        kv.generate("k")
        kv2 = m.KeyVault()
        kv2.load_private("k")
        pub = kv2.public_pem("k")
        import oqs
        with oqs.KeyEncapsulation(getattr(kv2, "KEM_ALG", "ML-KEM-768")) as kem:
            ct, ss = kem.encap_secret(pub)
        ss2 = kv2.key.decap_secret(ct)
        if ss != ss2:
            raise AssertionError("loaded key shared secret mismatch")


def test_14_encrypt_complex_pyc(m: Any) -> None:
    keygen_mod = _load_reference("13_pycryptodome_keygen_complex")
    with tempfile.TemporaryDirectory() as d:
        os.environ["KEY_DIR"] = d
        kv = keygen_mod.KeyVault()
        kv.generate("k")
        src = Path(d) / "in.txt"
        dst = Path(d) / "out.bin"
        rec = Path(d) / "recovered.txt"
        src.write_bytes(b"file contents")
        sender = m.EnvelopeCipher(public_key_path=Path(d) / "k.pub.bin")
        sender.encrypt_file(src, dst)
        receiver = m.EnvelopeCipher(private_key_path=Path(d) / "k.priv.bin")
        receiver.decrypt_file(dst, rec)
        if rec.read_bytes() != b"file contents":
            raise AssertionError("file roundtrip mismatch")


def test_15_sign_complex_pyc(m: Any) -> None:
    import oqs
    with tempfile.TemporaryDirectory() as d:
        signer = oqs.Signature("ML-DSA-65")
        pub = signer.generate_keypair()
        secret = signer.export_secret_key()
        (Path(d) / "k.priv.bin").write_bytes(secret)
        (Path(d) / "k.pub.bin").write_bytes(pub)
        artifact = Path(d) / "release.tar"
        sig = Path(d) / "release.sig"
        artifact.write_bytes(b"release artifact")
        s = m.ReleaseSigner(
            private_key_path=Path(d) / "k.priv.bin",
            public_key_path=Path(d) / "k.pub.bin",
        )
        s.sign_artifact(artifact, sig)
        if not s.verify_artifact(artifact, sig):
            raise AssertionError("release verify failed")


def test_16_kex_complex_pyc(m: Any) -> None:
    keygen_mod = _load_reference("13_pycryptodome_keygen_complex")
    with tempfile.TemporaryDirectory() as d:
        os.environ["KEY_DIR"] = d
        kv = keygen_mod.KeyVault()
        kv.generate("bob")
        wrapped = Path(d) / "wrapped.bin"
        alice = m.HandshakeBroker(peer_pub_path=Path(d) / "bob.pub.bin")
        sk_a = alice.initiate(wrapped)
        bob = m.HandshakeBroker(my_priv_path=Path(d) / "bob.priv.bin")
        sk_b = bob.respond(wrapped)
        if sk_a != sk_b:
            raise AssertionError("session keys differ")


# ──────────────────────────────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────────────────────────────

TESTS: dict[str, Callable[[Any], None]] = {
    "01": test_01_keygen_simple,
    "02": test_02_encrypt_simple,
    "03": test_03_sign_simple,
    "04": test_04_kex_simple,
    "05": test_05_keygen_complex,
    "06": test_06_encrypt_complex,
    "07": test_07_sign_complex,
    "08": test_08_kex_complex,
    "09": test_09_sign_simple_pyc,
    "10": test_10_keygen_simple_pyc,
    "11": test_11_encrypt_simple_pyc,
    "12": test_12_kex_simple_pyc,
    "13": test_13_keygen_complex_pyc,
    "14": test_14_encrypt_complex_pyc,
    "15": test_15_sign_complex_pyc,
    "16": test_16_kex_complex_pyc,
}


def _load_reference(name: str) -> Any:
    """Reference 모듈 로드 (다른 패턴의 keygen이 필요할 때 사용)."""
    ref_dir = Path(__file__).parent.parent / "benchmark" / "reference"
    return load_module(ref_dir / f"{name}.py", f"reference_{name}")


def run_test(pattern_id: str, module_path: Path) -> TestResult:
    if pattern_id not in TESTS:
        return TestResult(pattern_id, False, error=f"no test for pattern {pattern_id}")
    try:
        m = load_module(module_path, f"candidate_{pattern_id}")
    except Exception as e:
        return TestResult(pattern_id, False, error=f"import failed: {type(e).__name__}: {e}")
    try:
        TESTS[pattern_id](m)
        return TestResult(pattern_id, True)
    except Exception as e:
        return TestResult(
            pattern_id, False,
            error=f"{type(e).__name__}: {e}",
            details={"traceback": traceback.format_exc(limit=3)},
        )
