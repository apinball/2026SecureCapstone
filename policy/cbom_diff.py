#!/usr/bin/env python3
"""
cbom_diff.py — CBOM 마이그레이션 이력 비교

이전 실행의 CBOM과 현재 CBOM을 비교하여 migration_progress 필드를 추가합니다.
파이프라인 Step 10에서 호출됩니다.

Usage:
  python policy/cbom_diff.py --current <path> --previous <path> --out <path>
"""

import argparse
import json
import sys
from datetime import datetime, timezone


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def finding_key(r):
    return f"{r['file']}:{r['line']}:{r['rule']}"


def compare(current, previous):
    curr_count = current.get("migration_summary", {}).get("manual_action_required", 0)
    curr_findings = {finding_key(r) for r in current.get("classical_crypto_findings", [])}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if previous is None:
        # 첫 실행 — 기준선
        return {
            "compared_at": now,
            "status": "BASELINE",
            "note": "No previous CBOM found — this is the baseline run",
            "current_manual_required": curr_count,
            "delta": 0,
        }

    prev_count = previous.get("migration_summary", {}).get("manual_action_required", 0)
    prev_findings = {finding_key(r) for r in previous.get("classical_crypto_findings", [])}

    resolved = sorted(prev_findings - curr_findings)
    new_findings = sorted(curr_findings - prev_findings)
    delta = prev_count - curr_count

    if delta > 0:
        status = "IMPROVED"
    elif delta < 0:
        status = "REGRESSED"
    else:
        status = "UNCHANGED"

    progress = {
        "compared_at": now,
        "status": status,
        "previous_manual_required": prev_count,
        "current_manual_required": curr_count,
        "delta": delta,
        "resolved_count": len(resolved),
        "new_count": len(new_findings),
    }

    if resolved:
        progress["resolved"] = resolved
    if new_findings:
        progress["new_findings"] = new_findings

    return progress


def print_summary(progress):
    print("=== CBOM Migration Progress ===")
    status = progress["status"]

    if status == "BASELINE":
        print(f"[BASELINE] 첫 번째 실행 — 기준선 설정")
        print(f"  수동 조치 필요: {progress['current_manual_required']}건")
    else:
        prev = progress["previous_manual_required"]
        curr = progress["current_manual_required"]
        delta = progress["delta"]

        print(f"  이전: {prev}건 → 현재: {curr}건")

        if status == "IMPROVED":
            print(f"[IMPROVED] {delta}건 해결됨")
        elif status == "REGRESSED":
            print(f"[REGRESSED] {abs(delta)}건 증가 — 새로운 레거시 암호 사용 감지")
        else:
            print(f"[UNCHANGED] 변화 없음")

        if progress.get("resolved"):
            print(f"  해결된 항목 ({progress['resolved_count']}건):")
            for r in progress["resolved"]:
                print(f"    - {r}")
        if progress.get("new_findings"):
            print(f"  신규 발견 ({progress['new_count']}건):")
            for r in progress["new_findings"]:
                print(f"    - {r}")


def main():
    parser = argparse.ArgumentParser(description="CBOM 마이그레이션 이력 비교")
    parser.add_argument("--current", required=True, help="현재 CBOM JSON 경로")
    parser.add_argument("--previous", required=True, help="이전 CBOM JSON 경로 (없으면 BASELINE)")
    parser.add_argument("--out", required=True, help="출력 CBOM JSON 경로")
    args = parser.parse_args()

    current = load_json(args.current)
    if current is None:
        print(f"[ERROR] 현재 CBOM 파일을 읽을 수 없습니다: {args.current}", file=sys.stderr)
        sys.exit(1)

    previous = load_json(args.previous)

    progress = compare(current, previous)
    current["migration_progress"] = progress

    with open(args.out, "w") as f:
        json.dump(current, f, indent=2, ensure_ascii=False)

    print_summary(progress)
    print(f"[DONE] migration_progress 필드 추가 완료 → {args.out}")


if __name__ == "__main__":
    main()
