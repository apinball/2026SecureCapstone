#!/usr/bin/env python3
"""R4: Rollback loop prevention verification.

rollback.sh 가 무한 롤백 루프를 방지하는 두 가지 메커니즘을 정적 코드 검증으로 확인:

  M1: commit message에 '[skip ci]' 마커 포함
      → 롤백 커밋이 push되어도 GitHub Actions가 다음 파이프라인을 트리거하지 않음
  M2: 'git diff --cached --quiet' 가드
      → 이미 롤백 대상과 동일한 nginx.conf 라면 commit 자체를 생략

두 메커니즘 모두 존재해야 R4 PASS.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROLLBACK_SH = ROOT / "perf-rollback" / "rollback.sh"

CHECKS = [
    {
        "id": "M1",
        "desc": "Commit message includes [skip ci] marker",
        "pattern": r"\[skip ci\]",
        "rationale": "GitHub Actions skips workflow runs for commits with [skip ci] in the message",
    },
    {
        "id": "M2",
        "desc": "Empty-diff guard skips commit when no change",
        "pattern": r"git diff --cached --quiet",
        "rationale": "Prevents recursive rollback when nginx.conf already matches the rollback target",
    },
    {
        "id": "M3",
        "desc": "Stage 1 short-circuit (cannot rollback further)",
        "pattern": r'STAGE.*-eq 1',
        "rationale": "Stage 1 has no previous stage to roll back to, so the script exits early",
    },
]


def main():
    if not ROLLBACK_SH.exists():
        raise FileNotFoundError(f"rollback.sh not found at {ROLLBACK_SH}")

    src = ROLLBACK_SH.read_text(encoding="utf-8")

    results = []
    for c in CHECKS:
        found = bool(re.search(c["pattern"], src))
        results.append({
            "id": c["id"],
            "desc": c["desc"],
            "pattern": c["pattern"],
            "found": found,
            "rationale": c["rationale"],
            "match": "PASS" if found else "FAIL",
        })

    print(f"{'ID':<4} {'Found':<7} {'Mechanism':<55} {'Match':<6}")
    print("-" * 80)
    for r in results:
        print(f"{r['id']:<4} {str(r['found']):<7} {r['desc'][:53]:<55} {r['match']:<6}")

    pass_count = sum(1 for r in results if r["match"] == "PASS")
    print(f"\nLoop prevention mechanisms detected: {pass_count}/{len(results)}")

    out = Path(__file__).parent / "rollback_loop_results.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(
            {"results": results, "pass_n": pass_count, "pass_total": len(results),
             "loop_prevention_status": "PASS" if pass_count == len(results) else "PARTIAL"},
            f, indent=2, ensure_ascii=False
        )
    print(f"\n[SAVED] {out}")


if __name__ == "__main__":
    main()
