#!/usr/bin/env python3
"""Aggregate S1-S6 CBOM Diff scenario results into a summary table."""
import json
from pathlib import Path

BASE = Path(__file__).parent

SCENARIOS = [
    ("S1", "BASELINE", "s1_result.json", "First run (no previous CBOM)"),
    ("S2", "IMPROVED", "s2_result.json", "Stage 1 -> Stage 2 transition"),
    ("S3", "IMPROVED", "s3_result.json", "Stage 2 -> Stage 3 transition"),
    ("S4", "REGRESSED", "s4_result.json", "Stage 3 -> Stage 2 forced regression"),
    ("S5", "UNCHANGED", "s5_result.json", "Same stage re-run"),
    ("S6", "UNCHANGED", "s6_result.json", "Code-only change (no algorithm asset)"),
]


def main():
    results = []
    for sid, expected, outfile, desc in SCENARIOS:
        path = BASE / outfile
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        progress = None
        for p in d.get("properties", []):
            if "migration_progress" in p.get("name", ""):
                progress = json.loads(p["value"])
                break
        actual = progress["status"] if progress else "ERROR"
        match = "PASS" if actual == expected else "FAIL"
        delta = progress.get("delta") if progress else None
        results.append({
            "id": sid,
            "scenario": desc,
            "expected": expected,
            "actual": actual,
            "delta": delta,
            "match": match,
        })

    print(f"{'ID':<4} {'Expected':<12} {'Actual':<12} {'Delta':<8} {'Match':<6}")
    print("-" * 50)
    for r in results:
        print(f"{r['id']:<4} {r['expected']:<12} {r['actual']:<12} {str(r['delta']):<8} {r['match']:<6}")
    print()
    pass_count = sum(1 for r in results if r["match"] == "PASS")
    print(f"Total accuracy: {pass_count}/{len(results)}")

    out_path = BASE / "accuracy_summary.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {"results": results, "accuracy_n": pass_count, "accuracy_total": len(results),
             "accuracy_str": f"{pass_count}/{len(results)}"},
            f, indent=2, ensure_ascii=False
        )
    print(f"\n[SAVED] {out_path}")


if __name__ == "__main__":
    main()
