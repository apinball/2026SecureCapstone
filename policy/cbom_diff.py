#!/usr/bin/env python3
"""
cbom_diff.py — CycloneDX CBOM 마이그레이션 이력 비교

이전 실행의 CycloneDX CBOM과 현재 CBOM을 비교하여
migration_progress 정보를 properties에 추가합니다.
파이프라인 Step 10에서 호출됩니다.

CycloneDX 1.6 형식에서는 커스텀 데이터가 top-level "properties" 배열에
securecapstone: 네임스페이스로 저장됩니다.

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


def get_property(bom, name):
    """CycloneDX BOM의 top-level properties에서 특정 이름의 값을 꺼낸다."""
    for p in bom.get("properties", []):
        if p.get("name") == name:
            raw = p.get("value", "")
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return raw
    return None


def set_property(bom, name, value):
    """CycloneDX BOM의 top-level properties에 값을 설정(덮어쓰기)한다."""
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False)
    elif isinstance(value, bool):
        rendered = "true" if value else "false"
    else:
        rendered = str(value)

    props = bom.setdefault("properties", [])

    for p in props:
        if p.get("name") == name:
            p["value"] = rendered
            return

    props.append({"name": name, "value": rendered})


def finding_key(r):
    return f"{r['file']}:{r['line']}:{r['rule']}"


def compare(current_bom, previous_bom):
    """현재·이전 CBOM의 마이그레이션 정보를 비교하여 진척도 dict를 반환."""
    migration_summary = get_property(current_bom, "securecapstone:migration_summary") or {}
    findings = get_property(current_bom, "securecapstone:classical_crypto_findings") or []

    curr_count = 0
    if isinstance(migration_summary, dict):
        curr_count = migration_summary.get("manual_action_required", 0)
    curr_findings = set()
    if isinstance(findings, list):
        curr_findings = {finding_key(r) for r in findings if isinstance(r, dict)}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if previous_bom is None:
        return {
            "compared_at": now,
            "status": "BASELINE",
            "note": "No previous CBOM found — this is the baseline run",
            "current_manual_required": curr_count,
            "delta": 0,
        }

    prev_summary = get_property(previous_bom, "securecapstone:migration_summary") or {}
    prev_findings_list = get_property(previous_bom, "securecapstone:classical_crypto_findings") or []

    prev_count = 0
    if isinstance(prev_summary, dict):
        prev_count = prev_summary.get("manual_action_required", 0)
    prev_findings = set()
    if isinstance(prev_findings_list, list):
        prev_findings = {finding_key(r) for r in prev_findings_list if isinstance(r, dict)}

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

        resolved_count = progress.get("resolved_count", 0)
        new_count = progress.get("new_count", 0)

        if status == "IMPROVED":
            print(f"[IMPROVED] 해결 {resolved_count}건 / 신규 {new_count}건 (전체 {delta}건 감소)")
        elif status == "REGRESSED":
            print(f"[REGRESSED] 해결 {resolved_count}건 / 신규 {new_count}건 (전체 {abs(delta)}건 증가)")
        else:
            print(f"[UNCHANGED] 해결 {resolved_count}건 / 신규 {new_count}건 (변화 없음)")

        if progress.get("resolved"):
            print(f"  해결된 항목 ({progress['resolved_count']}건):")
            for r in progress["resolved"]:
                print(f"    - {r}")
        if progress.get("new_findings"):
            print(f"  신규 발견 ({progress['new_count']}건):")
            for r in progress["new_findings"]:
                print(f"    - {r}")


def main():
    parser = argparse.ArgumentParser(description="CycloneDX CBOM 마이그레이션 이력 비교")
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

    # CycloneDX properties에 migration_progress 추가
    set_property(current, "securecapstone:migration_progress", progress)

    with open(args.out, "w") as f:
        json.dump(current, f, indent=2, ensure_ascii=False)

    print_summary(progress)
    print(f"[DONE] securecapstone:migration_progress 속성 추가 완료 → {args.out}")


if __name__ == "__main__":
    main()
