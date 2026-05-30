#!/usr/bin/env python3
"""3-way consistency check experiment for cbom_gen.cross_validate().

Tests the validation.consistent field across multiple signal-mismatch scenarios:
  - C1: All three agree (Stage 2 across the board)         -> consistent=True
  - C2: Requested Stage 2 but server negotiates Stage 1    -> consistent=False
  - C3: cbom_gen says Stage 2 but verify script says Stage 3 -> consistent=False
  - C4: All three agree on Stage 3                          -> consistent=True
  - C5: Mismatch in all three signals                       -> consistent=False
"""
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from policy.cbom_gen import cross_validate

SCENARIOS = [
    {
        "id": "C1",
        "desc": "All three agree on Stage 2",
        "our_status": "STAGE_2_HYBRID_PQC",
        "script_judgement": "[OK] Stage 2 hybrid PQC negotiated",
        "requested_stage": "2",
        "expected_consistent": True,
    },
    {
        "id": "C2",
        "desc": "Requested Stage 2 but server negotiates Stage 1",
        "our_status": "STAGE_1_CLASSICAL",
        "script_judgement": "[OK] Stage 1 classical ECC",
        "requested_stage": "2",
        "expected_consistent": False,
    },
    {
        "id": "C3",
        "desc": "cbom_gen says Stage 2, verify script says Stage 3",
        "our_status": "STAGE_2_HYBRID_PQC",
        "script_judgement": "[OK] Stage 3 PQC hybrid",
        "requested_stage": "2",
        "expected_consistent": False,
    },
    {
        "id": "C4",
        "desc": "All three agree on Stage 3",
        "our_status": "STAGE_3_POST_QUANTUM",
        "script_judgement": "[OK] Stage 3 PQC hybrid",
        "requested_stage": "3",
        "expected_consistent": True,
    },
    {
        "id": "C5",
        "desc": "All three signals mismatch",
        "our_status": "STAGE_2_HYBRID_PQC",
        "script_judgement": "[OK] Stage 1 classical",
        "requested_stage": "3",
        "expected_consistent": False,
    },
]


def main():
    results = []
    for sc in SCENARIOS:
        val = cross_validate(sc["our_status"], sc["script_judgement"], sc["requested_stage"])
        actual = val.get("consistent", True)
        match = "PASS" if actual == sc["expected_consistent"] else "FAIL"
        warnings = val.get("warnings", [])
        results.append({
            "id": sc["id"],
            "scenario": sc["desc"],
            "expected_consistent": sc["expected_consistent"],
            "actual_consistent": actual,
            "warning_count": len(warnings),
            "warnings": warnings,
            "match": match,
        })

    print(f"{'ID':<4} {'Expected':<10} {'Actual':<10} {'Warnings':<10} {'Match':<6}")
    print("-" * 60)
    for r in results:
        print(f"{r['id']:<4} {str(r['expected_consistent']):<10} {str(r['actual_consistent']):<10} {r['warning_count']:<10} {r['match']:<6}")

    pass_count = sum(1 for r in results if r["match"] == "PASS")
    print(f"\nTotal: {pass_count}/{len(results)}")

    out = Path(__file__).parent / "consistency_results.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(
            {"results": results, "accuracy_n": pass_count, "accuracy_total": len(results),
             "accuracy_str": f"{pass_count}/{len(results)}"},
            f, indent=2, ensure_ascii=False
        )
    print(f"\n[SAVED] {out}")


if __name__ == "__main__":
    main()
