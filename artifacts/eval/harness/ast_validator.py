"""AST-based oqs-python API misuse detector.

PR #82의 ai-migration/migrate.py에서 발췌. 평가 하네스 독립성을 위해 복제.
LLM 출력의 "잘 알려진 환각 패턴"을 차단:
- 클래스 직접 호출 (KeyEncapsulation.generate_keypair() 등)
- 잘못된 메서드명 (encapsulate, encrypt 등)
- 모듈 레벨 인스턴스화 (race condition 위험)
- import 누락 (oqs 미사용)
"""
import ast


def validate_oqs_usage(source: str) -> tuple[bool, list[str]]:
    """반환: (전체 통과 여부, 발견된 문제 목록)."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return False, [f"AST parse error: {e}"]

    issues: list[str] = []
    uses_kem = False
    uses_sig = False
    has_kem_instance = False
    has_sig_instance = False

    # 1) import: oqs.KeyEncapsulation / oqs.Signature 또는 oqs 모듈 자체
    imports_oqs_module = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "oqs":
                    imports_oqs_module = True
        elif isinstance(node, ast.ImportFrom) and node.module == "oqs":
            for alias in node.names:
                if alias.name == "KeyEncapsulation":
                    uses_kem = True
                if alias.name == "Signature":
                    uses_sig = True

    # `import oqs` 후 `oqs.KeyEncapsulation(...)` 사용도 허용 — 호출 노드에서 별도 검증
    if imports_oqs_module and not (uses_kem or uses_sig):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "oqs":
                    if node.func.attr == "KeyEncapsulation":
                        uses_kem = True
                        has_kem_instance = True
                    elif node.func.attr == "Signature":
                        uses_sig = True
                        has_sig_instance = True

    if not (uses_kem or uses_sig):
        issues.append("oqs.KeyEncapsulation 또는 oqs.Signature 미사용 — 마이그레이션 미적용")
        return False, issues

    # 2) 인스턴스 생성 + 클래스 직접 호출 검사
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id == "KeyEncapsulation":
                    has_kem_instance = True
                elif func.id == "Signature":
                    has_sig_instance = True
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                cls = func.value.id
                if cls == "KeyEncapsulation":
                    issues.append(
                        f"KeyEncapsulation.{func.attr}() — 클래스 직접 호출 금지"
                    )
                elif cls == "Signature":
                    issues.append(
                        f"Signature.{func.attr}() — 클래스 직접 호출 금지"
                    )

    if uses_kem and not has_kem_instance:
        issues.append("KeyEncapsulation(...) 인스턴스 생성 패턴 없음")
    if uses_sig and not has_sig_instance:
        issues.append("Signature(...) 인스턴스 생성 패턴 없음")

    # 3) 잘못된 메서드명
    invalid_kem_calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            method_name = node.attr
            if uses_kem and method_name in {"encapsulate", "decapsulate", "encrypt", "decrypt"}:
                # encrypt/decrypt는 AES 컨텍스트일 수 있어 보수적으로만
                if method_name in {"encapsulate", "decapsulate"}:
                    invalid_kem_calls.append(method_name)
    if invalid_kem_calls:
        issues.append(
            f"잘못된 KEM 메서드: {sorted(set(invalid_kem_calls))} — 정답은 encap_secret/decap_secret"
        )

    # 4) 모듈 레벨 인스턴스화 (race condition)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(node.value, ast.Call):
                    func = node.value.func
                    fname = (
                        func.id if isinstance(func, ast.Name)
                        else func.attr if isinstance(func, ast.Attribute)
                        else None
                    )
                    if fname in {"KeyEncapsulation", "Signature"}:
                        issues.append(
                            f"모듈 레벨 {fname} 인스턴스화 — race condition 위험. 함수 내부 또는 클래스 멤버로 이동"
                        )

    return len(issues) == 0, issues
