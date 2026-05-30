#!/usr/bin/env python3
"""LLM 기반 PQC 마이그레이션 평가 하네스 (A-1).

각 패턴(N=16)에 대해 4단계 측정:
- L1: prompt only — LLM 호출, 원본 응답
- L2: + AST 검증 — oqs API 사용 적합성
- L3: + semantic test — 마이그레이션 결과를 실제 import해서 동작 확인
- L4: + equivalence — 정답과 구조적 일치 점수

사용:
  GITHUB_TOKEN=... python eval_runner.py --k 5
  python eval_runner.py --offline --use-reference   # 정답을 LLM 출력 자리에 넣어 dry-run
"""
import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from harness.ast_validator import validate_oqs_usage  # noqa: E402
from harness.llm_client import call_llm  # noqa: E402
from harness.semantic_tests import run_test  # noqa: E402
from harness.equivalence import equivalence_check  # noqa: E402

PATTERN_DIR = HERE / "benchmark" / "patterns"
REF_DIR = HERE / "benchmark" / "reference"
RESULTS_DIR = HERE / "benchmark" / "results"
PROMPT_FILE = HERE.parent.parent / "ai-migration" / "prompts" / "rsa_to_mlkem.txt"


def load_prompt() -> str:
    """PR #82 prompt를 로드. 없으면 fallback 인라인."""
    if PROMPT_FILE.exists():
        return PROMPT_FILE.read_text(encoding="utf-8")
    # PR #82 머지 전 환경 — 최소 fallback
    return (
        "Rewrite the following Python file to replace RSA with ML-KEM (oqs.KeyEncapsulation) "
        "for KEMs and ML-DSA (oqs.Signature) for signatures. "
        "Use generate_keypair / encap_secret / decap_secret / sign / verify exactly as in oqs-python. "
        "Return ONLY the rewritten file content.\n\n"
        "Findings: replace all RSA usages.\n\n"
        "Original file content:\n```\n{file_content}\n```\n"
    )


def render_prompt(template: str, file_content: str) -> str:
    return template.replace("{file_content}", file_content).replace(
        "{findings}", "RSA usage detected; migrate to PQC primitives."
    )


def strip_markdown_fences(text: str) -> str:
    """LLM이 프롬프트 무시하고 ```python ... ```로 감싸는 경우 처리.

    첫 ``` 블록이 있으면 그 내부만 반환. 없으면 원본 그대로.
    """
    if not text:
        return text
    lines = text.splitlines()
    # 첫 fence 시작 줄 찾기
    start = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("```"):
            start = i
            break
    if start is None:
        return text
    # 매칭되는 끝 fence
    end = None
    for j in range(start + 1, len(lines)):
        if lines[j].strip().startswith("```"):
            end = j
            break
    if end is None:
        # opening만 있고 closing 없음 → opening 다음부터 끝까지
        return "\n".join(lines[start + 1 :])
    return "\n".join(lines[start + 1 : end])


def list_patterns() -> list[Path]:
    return sorted(PATTERN_DIR.glob("*.py"))


def pattern_id(path: Path) -> str:
    return path.stem.split("_", 1)[0]


def evaluate_one(pattern_path: Path, candidate_source: str, ref_path: Path) -> dict:
    """L2/L3/L4 모두 수행. 입력: LLM 출력 source. 출력: 평가 결과 dict."""
    pid = pattern_id(pattern_path)

    # L2: AST 검증
    ast_ok, ast_issues = validate_oqs_usage(candidate_source)

    # L3: semantic test (L2 통과한 것만 의미 있지만 항상 시도)
    semantic_passed = False
    semantic_error: str | None = None
    if ast_ok:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(candidate_source)
            tmp_path = Path(f.name)
        try:
            res = run_test(pid, tmp_path)
            semantic_passed = res.passed
            semantic_error = res.error
        finally:
            tmp_path.unlink(missing_ok=True)
    else:
        semantic_error = "AST 검증 실패로 skip"

    # L4: equivalence
    eq_result = equivalence_check(ref_path.read_text(encoding="utf-8"), candidate_source)

    return {
        "pattern_id": pid,
        "L2_ast_ok": ast_ok,
        "L2_ast_issues": ast_issues,
        "L3_semantic_passed": semantic_passed,
        "L3_error": semantic_error,
        "L4_equivalence_score": eq_result.get("overall_score", 0.0),
        "L4_equivalent": eq_result.get("equivalent", False),
        "L4_mismatches": eq_result.get("mismatches", []),
    }


def run(k: int, offline: bool, use_reference: bool, output: Path) -> int:
    prompt_template = load_prompt()
    patterns = list_patterns()
    if not patterns:
        print("[eval] no patterns found", file=sys.stderr)
        return 1

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    all_results: list[dict] = []
    for pp in patterns:
        pid = pattern_id(pp)
        ref = REF_DIR / pp.name
        if not ref.exists():
            print(f"[eval] {pid}: reference missing, skip")
            continue
        file_content = pp.read_text(encoding="utf-8")
        prompt = render_prompt(prompt_template, file_content)

        for trial in range(k):
            print(f"[eval] pattern {pid} trial {trial+1}/{k}", flush=True)

            if offline:
                if use_reference:
                    candidate = ref.read_text(encoding="utf-8")
                    llm_error = None
                else:
                    candidate = file_content  # baseline: do nothing — should fail L2
                    llm_error = None
            else:
                raw, llm_error = call_llm(prompt)
                if raw is None:
                    raw = ""
                candidate = strip_markdown_fences(raw)

            entry: dict = {
                "pattern_id": pid,
                "pattern_file": pp.name,
                "trial": trial,
                "llm_error": llm_error,
                "candidate_chars": len(candidate),
                "candidate_preview": candidate[:300],
            }
            if candidate:
                entry.update(evaluate_one(pp, candidate, ref))
            else:
                entry.update({"L2_ast_ok": False, "L3_semantic_passed": False, "L4_equivalent": False})
            all_results.append(entry)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "k": k,
                "offline": offline,
                "use_reference": use_reference,
                "n_patterns": len(patterns),
                "results": all_results,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    summary(all_results)
    print(f"\n[eval] results saved → {output}")
    return 0


def summary(results: list[dict]) -> None:
    n = len(results)
    if n == 0:
        return
    l2 = sum(1 for r in results if r.get("L2_ast_ok"))
    l3 = sum(1 for r in results if r.get("L3_semantic_passed"))
    l4 = sum(1 for r in results if r.get("L4_equivalent"))
    print("\n=== summary ===")
    print(f"trials: {n}")
    print(f"L2 (AST ok):           {l2}/{n} = {l2/n:.1%}")
    print(f"L3 (semantic passed):  {l3}/{n} = {l3/n:.1%}")
    print(f"L4 (equivalent):       {l4}/{n} = {l4/n:.1%}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=1, help="trials per pattern")
    ap.add_argument("--offline", action="store_true", help="skip LLM calls")
    ap.add_argument(
        "--use-reference",
        action="store_true",
        help="(offline) use reference solutions as candidate — sanity check the harness",
    )
    ap.add_argument(
        "--output",
        default=str(HERE / "benchmark" / "results" / "eval.json"),
        help="output JSON path",
    )
    args = ap.parse_args()
    return run(args.k, args.offline, args.use_reference, Path(args.output))


if __name__ == "__main__":
    sys.exit(main())
