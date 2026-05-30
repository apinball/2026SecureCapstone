"""AST 구조 매칭으로 LLM 출력과 정답 사이의 의미 동등성 근사.

완전한 의미 동등성 분석은 결정 불가능. 여기서는 다음 features를 구조적으로 비교:
- 사용된 oqs API 호출 (KeyEncapsulation/Signature 인스턴스 생성, encap/decap, sign/verify)
- AES-GCM 결합 여부 (암호화 패턴에서 핵심)
- 함수/클래스 이름과 시그니처 매칭
- import된 라이브러리 집합

결과는 `feature_match_ratio`로 0~1 점수. 0.8 이상이면 "동등하다고 간주".
"""
import ast
from dataclasses import dataclass, field


@dataclass
class CryptoFeatures:
    has_kem_instance: bool = False
    has_sig_instance: bool = False
    calls_encap: bool = False
    calls_decap: bool = False
    calls_sign: bool = False
    calls_verify: bool = False
    uses_aesgcm: bool = False
    function_names: set[str] = field(default_factory=set)
    class_names: set[str] = field(default_factory=set)


def extract(source: str) -> tuple[CryptoFeatures | None, str | None]:
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return None, f"parse error: {e}"

    f = CryptoFeatures()

    for node in ast.walk(tree):
        # 함수/클래스 이름
        if isinstance(node, ast.FunctionDef):
            f.function_names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            f.class_names.add(node.name)
        # 호출 분석
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id == "KeyEncapsulation":
                    f.has_kem_instance = True
                elif func.id == "Signature":
                    f.has_sig_instance = True
                elif func.id == "AESGCM":
                    f.uses_aesgcm = True
            elif isinstance(func, ast.Attribute):
                attr = func.attr
                if attr == "encap_secret":
                    f.calls_encap = True
                elif attr == "decap_secret":
                    f.calls_decap = True
                elif attr in ("sign", "encrypt_and_digest") and isinstance(func.value, ast.Name):
                    if attr == "sign":
                        f.calls_sign = True
                elif attr == "verify":
                    f.calls_verify = True
                elif attr == "KeyEncapsulation" and isinstance(func.value, ast.Name) and func.value.id == "oqs":
                    f.has_kem_instance = True
                elif attr == "Signature" and isinstance(func.value, ast.Name) and func.value.id == "oqs":
                    f.has_sig_instance = True
                elif attr == "AESGCM":
                    f.uses_aesgcm = True
                elif attr == "new" and isinstance(func.value, ast.Name) and func.value.id == "AES":
                    f.uses_aesgcm = True  # PyCryptodome AES.new(MODE_GCM)
                elif attr == "sign":
                    f.calls_sign = True

    return f, None


def compare(reference: CryptoFeatures, candidate: CryptoFeatures) -> dict:
    """반환: {feature_match_ratio, mismatches}"""
    keys = [
        "has_kem_instance",
        "has_sig_instance",
        "calls_encap",
        "calls_decap",
        "calls_sign",
        "calls_verify",
        "uses_aesgcm",
    ]
    matches = 0
    total = 0
    mismatches: list[str] = []
    for k in keys:
        rv = getattr(reference, k)
        cv = getattr(candidate, k)
        # 정답이 True인 것만 매칭 강제
        if rv:
            total += 1
            if cv:
                matches += 1
            else:
                mismatches.append(f"{k}: reference uses but candidate does not")

    # 함수명 보존 비율
    if reference.function_names:
        common = reference.function_names & candidate.function_names
        fn_ratio = len(common) / len(reference.function_names)
    else:
        fn_ratio = 1.0
    if reference.class_names:
        common_cls = reference.class_names & candidate.class_names
        cls_ratio = len(common_cls) / len(reference.class_names)
    else:
        cls_ratio = 1.0

    feature_ratio = matches / total if total else 1.0
    # 가중 평균: 의미 features 70%, 이름 보존 30%
    score = 0.7 * feature_ratio + 0.15 * fn_ratio + 0.15 * cls_ratio

    return {
        "feature_match_ratio": round(feature_ratio, 3),
        "function_name_ratio": round(fn_ratio, 3),
        "class_name_ratio": round(cls_ratio, 3),
        "overall_score": round(score, 3),
        "equivalent": score >= 0.8,
        "mismatches": mismatches,
    }


def equivalence_check(reference_source: str, candidate_source: str) -> dict:
    ref, ref_err = extract(reference_source)
    cand, cand_err = extract(candidate_source)
    if ref is None:
        return {"error": f"reference: {ref_err}", "equivalent": False, "overall_score": 0.0}
    if cand is None:
        return {"error": f"candidate: {cand_err}", "equivalent": False, "overall_score": 0.0}
    return compare(ref, cand)
