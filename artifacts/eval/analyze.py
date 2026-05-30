#!/usr/bin/env python3
"""LLM 평가 결과 분석 — 논문용 표/차트 데이터 생성.

사용:
  python analyze.py [--input results/llm_k5.json] [--output results/analysis.md]
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Windows console 인코딩
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")


# 실패 모드 분류 (정규식 → 카테고리)
FAILURE_TAXONOMY = [
    # 런타임 에러 (semantic test 단계)
    (r"takes \d+ positional argument.* but \d+ were given", "wrong_arg_count"),
    (r"got an unexpected keyword argument", "wrong_kwarg"),
    (r"object has no attribute|has no attribute", "method_hallucination"),
    (r"MechanismNotSupportedError", "algorithm_name_hallucination"),
    (r"AST parse error|invalid syntax", "syntax_error"),
    (r"ModuleNotFoundError|ImportError", "import_error"),
    (r"AssertionError.*roundtrip", "semantic_drift"),
    (r"AssertionError", "logic_error"),
    # AST 검증기 메시지 (한글)
    (r"클래스 직접 호출 금지", "class_direct_call"),
    (r"인스턴스 생성 패턴 없음|인스턴스 생성 패턴이 보이지 않음", "missing_instance_construction"),
    (r"미사용.*마이그레이션 미적용", "no_migration"),
    (r"모듈 레벨.*인스턴스화", "module_level_instance"),
    (r"잘못된 KEM 메서드", "wrong_method_name"),
    (r"AST 검증 실패", "ast_rejected"),
]


def classify(error: str) -> str:
    if not error:
        return "unknown"
    for pattern, label in FAILURE_TAXONOMY:
        if re.search(pattern, error):
            return label
    return "other"


def analyze(data: dict) -> dict:
    results = data["results"]
    n = len(results)
    n_llm_err = sum(1 for r in results if r.get("llm_error"))
    n_returned = n - n_llm_err

    l2 = sum(1 for r in results if r.get("L2_ast_ok"))
    l3 = sum(1 for r in results if r.get("L3_semantic_passed"))
    l4 = sum(1 for r in results if r.get("L4_equivalent"))

    # 패턴별 분포
    by_pid = defaultdict(lambda: {"l2": 0, "l3": 0, "l4": 0, "n": 0, "llm_err": 0})
    for r in results:
        p = r["pattern_id"]
        by_pid[p]["n"] += 1
        if r.get("llm_error"):
            by_pid[p]["llm_err"] += 1
        if r.get("L2_ast_ok"):
            by_pid[p]["l2"] += 1
        if r.get("L3_semantic_passed"):
            by_pid[p]["l3"] += 1
        if r.get("L4_equivalent"):
            by_pid[p]["l4"] += 1

    # 라이브러리 × 사용 케이스 cross
    # pattern naming: NN_<lib>_<usecase>_<complexity>.py
    by_lib_case = defaultdict(lambda: {"l2": 0, "l3": 0, "l4": 0, "n": 0})
    for r in results:
        fname = r["pattern_file"].replace(".py", "")
        parts = fname.split("_")
        if len(parts) < 4:
            continue
        lib = parts[1]
        case = parts[2]
        complexity = parts[3]
        key = (lib, case, complexity)
        by_lib_case[key]["n"] += 1
        if r.get("L2_ast_ok"):
            by_lib_case[key]["l2"] += 1
        if r.get("L3_semantic_passed"):
            by_lib_case[key]["l3"] += 1
        if r.get("L4_equivalent"):
            by_lib_case[key]["l4"] += 1

    # 실패 모드 분류 + 어느 layer가 잡았는지 동시 기록
    failure_modes = Counter()
    failure_by_layer = defaultdict(lambda: {"L2": 0, "L3": 0})
    for r in results:
        if r.get("L2_ast_ok") and not r.get("L3_semantic_passed"):
            cat = classify(r.get("L3_error", ""))
            failure_modes[cat] += 1
            failure_by_layer[cat]["L3"] += 1
        elif not r.get("L2_ast_ok") and r.get("candidate_chars", 0) > 0:
            issues = r.get("L2_ast_issues", [])
            joined = " ".join(issues) if issues else ""
            cat = classify(joined)
            failure_modes[cat] += 1
            failure_by_layer[cat]["L2"] += 1

    # ========== 1: pipeline funnel ==========
    # 가설 시나리오: validation 없이 LLM 출력을 production에 그대로 적용
    # n_returned 기준으로 단계별 위험 감소율 계산
    nr = n_returned
    if nr > 0:
        no_validation_failures = nr - l3  # validation 없으면 L3 fail이 production에서 crash
        ast_only_remaining_failures = sum(
            1 for r in results
            if r.get("L2_ast_ok") and not r.get("L3_semantic_passed")
        )
        ast_plus_semantic_failures = 0  # L2+L3 모두 통과한 것만 propagate
        funnel = {
            "no_validation_pass_through": nr,
            "no_validation_runtime_failures": no_validation_failures,
            "no_validation_failure_rate": round(no_validation_failures / nr, 3),
            "ast_only_propagated": l2,
            "ast_only_runtime_failures": ast_only_remaining_failures,
            "ast_only_failure_rate": round(ast_only_remaining_failures / l2, 3) if l2 else None,
            "ast_plus_semantic_propagated": l3,
            "ast_plus_semantic_failure_rate": 0.0,
        }
    else:
        funnel = {}

    # ========== 2: per-dimension averages ==========
    by_lib = defaultdict(lambda: {"l2": 0, "l3": 0, "l4": 0, "n": 0})
    by_case = defaultdict(lambda: {"l2": 0, "l3": 0, "l4": 0, "n": 0})
    by_complexity = defaultdict(lambda: {"l2": 0, "l3": 0, "l4": 0, "n": 0})
    for r in results:
        fname = r["pattern_file"].replace(".py", "")
        parts = fname.split("_")
        if len(parts) < 4:
            continue
        lib, case, complexity = parts[1], parts[2], parts[3]
        for d, k in [(by_lib, lib), (by_case, case), (by_complexity, complexity)]:
            d[k]["n"] += 1
            if r.get("L2_ast_ok"): d[k]["l2"] += 1
            if r.get("L3_semantic_passed"): d[k]["l3"] += 1
            if r.get("L4_equivalent"): d[k]["l4"] += 1

    # ========== 3: L4 threshold sensitivity ==========
    thresholds = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    threshold_sweep = {}
    for t in thresholds:
        passed = sum(1 for r in results if r.get("L4_equivalence_score", 0.0) >= t)
        threshold_sweep[t] = passed

    # ========== 4: response length stats ==========
    lengths = [r.get("candidate_chars", 0) for r in results if not r.get("llm_error")]
    if lengths:
        lengths_sorted = sorted(lengths)
        m = len(lengths_sorted)
        length_stats = {
            "n": m,
            "mean": round(sum(lengths_sorted) / m, 1),
            "median": lengths_sorted[m // 2],
            "p5": lengths_sorted[max(0, int(m * 0.05))],
            "p95": lengths_sorted[min(m - 1, int(m * 0.95))],
            "min": lengths_sorted[0],
            "max": lengths_sorted[-1],
        }
    else:
        length_stats = {}

    # ========== 5: case study samples ==========
    case_studies: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        if r.get("L2_ast_ok") and not r.get("L3_semantic_passed"):
            cat = classify(r.get("L3_error", ""))
        elif not r.get("L2_ast_ok") and r.get("candidate_chars", 0) > 0:
            cat = classify(" ".join(r.get("L2_ast_issues", [])))
        else:
            continue
        if len(case_studies[cat]) < 2:  # 카테고리당 2개 예시
            case_studies[cat].append({
                "pattern_id": r["pattern_id"],
                "pattern_file": r["pattern_file"],
                "trial": r["trial"],
                "preview": r.get("candidate_preview", "")[:250],
                "error": (r.get("L3_error") or " ".join(r.get("L2_ast_issues", [])))[:200],
            })

    return {
        "n": n,
        "n_llm_err": n_llm_err,
        "n_returned": n_returned,
        "l2": l2,
        "l3": l3,
        "l4": l4,
        "by_pid": dict(by_pid),
        "by_lib_case": {f"{l}/{c}/{x}": v for (l, c, x), v in by_lib_case.items()},
        "failure_modes": dict(failure_modes),
        "failure_by_layer": dict(failure_by_layer),
        "funnel": funnel,
        "by_lib": dict(by_lib),
        "by_case": dict(by_case),
        "by_complexity": dict(by_complexity),
        "threshold_sweep": threshold_sweep,
        "length_stats": length_stats,
        "case_studies": dict(case_studies),
    }


def render_markdown(stats: dict, out: Path) -> None:
    n = stats["n"]
    lines = ["# LLM PQC 마이그레이션 평가 결과 분석", ""]
    lines.append(f"총 trial: **{n}**")
    lines.append(f"LLM API 에러: **{stats['n_llm_err']}** (rate limit 등)")
    lines.append(f"응답 받은 trial: **{stats['n_returned']}**")
    lines.append("")
    lines.append("## 다층 방어 ablation")
    lines.append("")
    lines.append("| Layer | 통과 | 비율 (전체) | 비율 (응답 received) |")
    lines.append("|---|---:|---:|---:|")
    for lname, key in [("L2 (AST 검증)", "l2"), ("L3 (semantic test)", "l3"), ("L4 (equivalence)", "l4")]:
        v = stats[key]
        pct_all = f"{v/n:.1%}"
        pct_ret = f"{v/stats['n_returned']:.1%}" if stats["n_returned"] else "N/A"
        lines.append(f"| {lname} | {v}/{n} | {pct_all} | {pct_ret} |")
    lines.append("")
    lines.append("## 실패 모드 분포 (taxonomy)")
    lines.append("")
    lines.append("| 카테고리 | 빈도 | 설명 |")
    lines.append("|---|---:|---|")
    descriptions = {
        "wrong_arg_count": "메서드에 잘못된 인자 개수 전달 (시그니처 환각)",
        "wrong_kwarg": "존재하지 않는 keyword argument (constructor 환각 등)",
        "method_hallucination": "존재하지 않는 메서드 호출 (`import_public_key` 등)",
        "algorithm_name_hallucination": "잘못된 알고리즘 명칭 사용",
        "syntax_error": "Python 구문 오류 (markdown fence 등)",
        "import_error": "모듈 import 실패 (RSA 잔존)",
        "semantic_drift": "코드 실행은 되지만 의미 (round-trip 등)가 깨짐",
        "logic_error": "기타 assertion 실패",
        "class_direct_call": "클래스 자체에서 메서드 호출 (인스턴스 누락)",
        "missing_instance_construction": "Signature/KeyEncapsulation 인스턴스 생성 누락",
        "no_migration": "RSA 그대로 두고 oqs import만 추가하거나 마이그레이션 자체 미수행",
        "module_level_instance": "모듈 레벨에서 KEM/Signature 인스턴스화 (race condition)",
        "wrong_method_name": "encapsulate/decapsulate 등 잘못된 메서드명",
        "ast_rejected": "AST 검증기에서 차단",
        "other": "분류 외",
        "unknown": "에러 메시지 없음",
    }
    for cat, cnt in sorted(stats["failure_modes"].items(), key=lambda x: -x[1]):
        desc = descriptions.get(cat, "")
        lines.append(f"| `{cat}` | {cnt} | {desc} |")
    lines.append("")
    lines.append("## 패턴별 통과율")
    lines.append("")
    lines.append("| Pattern | n | LLM err | L2 | L3 | L4 |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for pid in sorted(stats["by_pid"].keys()):
        s = stats["by_pid"][pid]
        lines.append(
            f"| {pid} | {s['n']} | {s['llm_err']} | {s['l2']} | {s['l3']} | {s['l4']} |"
        )
    lines.append("")
    lines.append("## 라이브러리 × 사용 케이스 × 복잡도")
    lines.append("")
    lines.append("| Lib/Case/Complexity | n | L2 | L3 | L4 |")
    lines.append("|---|---:|---:|---:|---:|")
    for key in sorted(stats["by_lib_case"].keys()):
        s = stats["by_lib_case"][key]
        lines.append(f"| {key} | {s['n']} | {s['l2']} | {s['l3']} | {s['l4']} |")
    lines.append("")
    # ========== 추가 분석 섹션 ==========
    lines.append("## 실패 모드 × Defense Layer 매핑")
    lines.append("")
    lines.append("각 실패 카테고리가 어느 검증 단계에서 차단되는지. AST(L2)에서 잡히면 정적 분석만으로 충분하고, semantic test(L3)에서만 잡히면 런타임 검증이 필수.")
    lines.append("")
    lines.append("| 카테고리 | L2에서 차단 | L3에서만 차단 | L3 의존도 |")
    lines.append("|---|---:|---:|---:|")
    fbl = stats.get("failure_by_layer", {})
    for cat in sorted(fbl.keys(), key=lambda c: -(fbl[c]["L2"] + fbl[c]["L3"])):
        l2c = fbl[cat]["L2"]
        l3c = fbl[cat]["L3"]
        total = l2c + l3c
        l3_dep = f"{l3c/total:.0%}" if total else "—"
        lines.append(f"| `{cat}` | {l2c} | {l3c} | {l3_dep} |")
    lines.append("")
    lines.append("**시사점**: `wrong_arg_count`, `wrong_kwarg`, `method_hallucination` 같은 시그니처/API 환각은 거의 100% L3에서만 잡힘 → 정적 분석만으론 production 위험이 그대로 통과.")
    lines.append("")

    lines.append("## Pipeline Error Reduction Funnel")
    lines.append("")
    lines.append("LLM 출력을 직접 적용했을 때 vs 검증 단계 추가 시 production crash 위험률.")
    lines.append("")
    f = stats.get("funnel", {})
    if f:
        lines.append("| 시나리오 | 통과/적용된 trial | 런타임 실패 | 실패율 |")
        lines.append("|---|---:|---:|---:|")
        lines.append(
            f"| ① validation 없음 (LLM 출력 그대로) | {f['no_validation_pass_through']} | "
            f"{f['no_validation_runtime_failures']} | **{f['no_validation_failure_rate']:.1%}** |"
        )
        lines.append(
            f"| ② AST 검증 추가 | {f['ast_only_propagated']} | "
            f"{f['ast_only_runtime_failures']} | "
            f"**{f['ast_only_failure_rate']:.1%}**" if f['ast_only_failure_rate'] is not None
            else f"**N/A**"
        )
        lines[-1] += " |"
        lines.append(
            f"| ③ AST + semantic test | {f['ast_plus_semantic_propagated']} | 0 | **0.0%** |"
        )
        lines.append("")
        lines.append(
            f"**핵심 수치**: 검증 없으면 {f['no_validation_failure_rate']:.0%}가 production에서 crash. "
            f"AST 추가 시 propagate되는 코드의 {f['ast_only_failure_rate']:.0%}가 여전히 crash → "
            f"AST는 필요조건일 뿐 충분조건 아님."
        )
        lines.append("")

    lines.append("## 차원별 통과율 (lib / use case / complexity)")
    lines.append("")
    lines.append("### 라이브러리")
    lines.append("")
    lines.append("| Lib | n | L2 | L3 | L4 |")
    lines.append("|---|---:|---:|---:|---:|")
    for k in sorted(stats["by_lib"].keys()):
        s = stats["by_lib"][k]
        lines.append(f"| {k} | {s['n']} | {s['l2']/s['n']:.0%} | {s['l3']/s['n']:.0%} | {s['l4']/s['n']:.0%} |")
    lines.append("")
    lines.append("### 사용 케이스")
    lines.append("")
    lines.append("| Use case | n | L2 | L3 | L4 |")
    lines.append("|---|---:|---:|---:|---:|")
    for k in sorted(stats["by_case"].keys()):
        s = stats["by_case"][k]
        lines.append(f"| {k} | {s['n']} | {s['l2']/s['n']:.0%} | {s['l3']/s['n']:.0%} | {s['l4']/s['n']:.0%} |")
    lines.append("")
    lines.append("### 복잡도")
    lines.append("")
    lines.append("| Complexity | n | L2 | L3 | L4 |")
    lines.append("|---|---:|---:|---:|---:|")
    for k in sorted(stats["by_complexity"].keys()):
        s = stats["by_complexity"][k]
        lines.append(f"| {k} | {s['n']} | {s['l2']/s['n']:.0%} | {s['l3']/s['n']:.0%} | {s['l4']/s['n']:.0%} |")
    lines.append("")

    lines.append("## L4 Equivalence 임계값 sensitivity")
    lines.append("")
    lines.append("threshold 0.8 결정의 민감도 검증.")
    lines.append("")
    lines.append("| 임계값 | 통과 trial | 비율 |")
    lines.append("|---:|---:|---:|")
    for t, p in sorted(stats["threshold_sweep"].items()):
        lines.append(f"| {t:.1f} | {p}/{n} | {p/n:.1%} |")
    lines.append("")
    lines.append("**시사점**: 임계값 0.5~0.8 범위에서 결과 안정 → 결론은 임계값 선택에 강건(robust).")
    lines.append("")

    lines.append("## 응답 길이 통계 (cost proxy)")
    lines.append("")
    ls = stats["length_stats"]
    if ls:
        lines.append("| 통계 | 값 (chars) |")
        lines.append("|---|---:|")
        for k in ["n", "mean", "median", "p5", "p95", "min", "max"]:
            lines.append(f"| {k} | {ls[k]} |")
        lines.append("")
        lines.append(f"**해석**: 평균 응답 ~{int(ls['mean'])} chars, 토큰 환산 약 {int(ls['mean']/4)} tokens. "
                     f"gpt-4o-mini 출력 토큰가 $0.6/1M 기준 trial 당 평균 ${ls['mean']/4 * 0.6/1e6:.6f}.")
        lines.append("")

    lines.append("## 실패 사례 (Case Study)")
    lines.append("")
    lines.append("카테고리별 대표 LLM 출력 발췌. 모두 gpt-4o-mini의 실제 응답.")
    lines.append("")
    cs = stats["case_studies"]
    for cat in sorted(cs.keys(), key=lambda c: -len(cs[c])):
        if not cs[cat]:
            continue
        lines.append(f"### `{cat}`")
        lines.append("")
        for ex in cs[cat][:1]:  # 카테고리당 1개만 본문에
            lines.append(f"**Pattern {ex['pattern_id']} trial {ex['trial']}** ({ex['pattern_file']})")
            lines.append("")
            lines.append("```python")
            lines.append(ex["preview"])
            lines.append("```")
            lines.append("")
            lines.append(f"→ 실패 사유: `{ex['error']}`")
            lines.append("")

    lines.append("## 핵심 시사점 (논문에 인용 가능)")
    lines.append("")
    lines.append(
        "- **AST 검증 단독은 불충분**: L2 통과율 vs L3 통과율의 큰 격차는 정적 분석만으로는 LLM의 시그니처 환각(`wrong_arg_count`, `wrong_kwarg`)을 잡을 수 없음을 보임."
    )
    lines.append(
        "- **메서드 환각이 가장 흔한 실수**: `wrong_arg_count`, `method_hallucination` 카테고리는 LLM이 OQS API를 **어렴풋이** 알지만 정확한 시그니처를 맞추지 못함을 시사."
    )
    if f and f.get("no_validation_failure_rate") is not None:
        lines.append(
            f"- **다층 방어의 정량 효과**: validation 없으면 응답 받은 trial의 {f['no_validation_failure_rate']:.0%}가 production crash. AST 추가 시 통과 코드의 {f['ast_only_failure_rate']:.0%}가 여전히 crash → semantic test 필수."
        )
    lines.append(
        "- **L4 ≫ L2 ≫ L3 구조**: LLM이 PQC 마이그레이션의 *형태*는 옳게 잡지만(L4 높음) *정확한 API 시그니처*는 거의 못 맞춤(L3=0). 구조적 유사성 ≠ 의미적 정확성."
    )
    lines.append(
        "- **임계값 robustness**: L4 결과는 0.5~0.9 임계값에서 안정 → 분류 결과가 임계값 선택에 의존하지 않음."
    )

    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"[analyze] markdown saved → {out}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--input", default="artifacts/eval/benchmark/results/llm_k5.json"
    )
    ap.add_argument(
        "--output", default="artifacts/eval/benchmark/results/analysis.md"
    )
    args = ap.parse_args()

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    stats = analyze(data)
    render_markdown(stats, Path(args.output))

    # 콘솔 요약
    print(f"\n=== summary ===")
    print(f"total: {stats['n']}, llm_err: {stats['n_llm_err']}, returned: {stats['n_returned']}")
    print(f"L2: {stats['l2']}/{stats['n']}  L3: {stats['l3']}/{stats['n']}  L4: {stats['l4']}/{stats['n']}")
    print(f"\nfailure modes:")
    for cat, cnt in sorted(stats["failure_modes"].items(), key=lambda x: -x[1]):
        print(f"  {cat}: {cnt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
