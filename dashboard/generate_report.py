#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DevSecOps PQC Pipeline — HTML 대시보드 리포트 생성기

GitHub Actions 파이프라인이 생성한 JSON 결과물을 읽어
발표/시연에 바로 쓸 수 있는 단일 HTML 파일을 만든다.

- 외부 CDN / 프레임워크 의존성 없음 (self-contained)
- Python 표준 라이브러리만 사용
- 입력 JSON 일부가 없거나 형식이 달라도 "데이터 없음"으로 graceful fallback

사용 예:
    python dashboard/generate_report.py \\
        --stage 2 --run-number 99 \\
        --out artifacts/pipeline-dashboard.html
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import os
import sys
from typing import Any


# ---------------------------------------------------------------------------
# JSON 안전 로더
# ---------------------------------------------------------------------------
def load_json(path: str) -> Any | None:
    """파일이 없거나 JSON 파싱 실패 시 None 반환."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def maybe_decode_json(value: Any) -> Any:
    """문자열이 JSON 직렬화된 값이면 decode, 아니면 원문 반환."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


# ---------------------------------------------------------------------------
# CBOM properties 파서 (CycloneDX)
# ---------------------------------------------------------------------------
def get_cbom_property(cbom: dict | None, name: str) -> Any:
    if not isinstance(cbom, dict):
        return None
    props = cbom.get("properties") or []
    for p in props:
        if isinstance(p, dict) and p.get("name") == name:
            return maybe_decode_json(p.get("value"))
    return None


# ---------------------------------------------------------------------------
# 상태(pass/fail/warning/unknown) 정규화
# ---------------------------------------------------------------------------
STATUS_PASS = "success"
STATUS_FAIL = "fail"
STATUS_WARN = "warning"
STATUS_UNKNOWN = "unknown"

_RAW_STATUS_MAP = {
    "pass": STATUS_PASS,
    "passed": STATUS_PASS,
    "success": STATUS_PASS,
    "ok": STATUS_PASS,
    "complete": STATUS_PASS,
    "fail": STATUS_FAIL,
    "failed": STATUS_FAIL,
    "error": STATUS_FAIL,
    "warn": STATUS_WARN,
    "warning": STATUS_WARN,
    "partial": STATUS_WARN,
    "regressed": STATUS_WARN,
}


def normalize_status(raw: Any) -> str:
    if raw is None:
        return STATUS_UNKNOWN
    key = str(raw).strip().lower()
    return _RAW_STATUS_MAP.get(key, STATUS_UNKNOWN)


def status_icon(status: str) -> str:
    return {
        STATUS_PASS: "✅",
        STATUS_FAIL: "❌",
        STATUS_WARN: "⚠️",
        STATUS_UNKNOWN: "❔",
    }.get(status, "❔")


def status_label_ko(status: str) -> str:
    return {
        STATUS_PASS: "성공",
        STATUS_FAIL: "실패",
        STATUS_WARN: "주의",
        STATUS_UNKNOWN: "확인불가",
    }.get(status, "확인불가")


# ---------------------------------------------------------------------------
# 파이프라인 단계별 상태 추론
# ---------------------------------------------------------------------------
def build_timeline(
    scan_summary: dict | None,
    crypto_findings: dict | None,
    tls_summary: dict | None,
    cbom: dict | None,
) -> list[dict]:
    """
    현재 JSON으로 100% 정확한 단계 추적이 불가능하므로
    "합리적 추론"으로 단계 상태를 결정한다. 불확실하면 unknown.
    """
    # 공통 파생값
    scan_ok = isinstance(scan_summary, dict)
    tools = (scan_summary or {}).get("tools") or {}
    findings_list = (crypto_findings or {}).get("results") or []
    findings_count = len(findings_list) if isinstance(findings_list, list) else 0

    overall_scan = normalize_status((scan_summary or {}).get("overall"))
    trivy = normalize_status(tools.get("trivy"))
    gitleaks = normalize_status(tools.get("gitleaks"))
    semgrep = normalize_status(tools.get("semgrep"))

    tls_result = normalize_status((tls_summary or {}).get("result"))
    cbom_present = isinstance(cbom, dict)

    migration_summary = get_cbom_property(cbom, "securecapstone:migration_summary")
    migration_status = STATUS_UNKNOWN
    if isinstance(migration_summary, dict):
        migration_status = normalize_status(migration_summary.get("status"))

    steps: list[dict] = [
        {
            "title": "저장소 Checkout & Stage 준비",
            "desc": "소스 코드 및 nginx.conf Stage 감지",
            # CBOM/스캔이 하나라도 있다면 최소한 체크아웃은 성공한 것으로 간주
            "status": STATUS_PASS if (scan_ok or cbom_present) else STATUS_UNKNOWN,
        },
        {
            "title": "PQC 자동 마이그레이션",
            "desc": "Classical TLS → Hybrid PQC-TLS 자동 교체",
            # 자동 마이그레이션 여부는 JSON만으로 확답 불가 → unknown
            "status": STATUS_UNKNOWN
            if migration_status == STATUS_UNKNOWN
            else (
                STATUS_PASS
                if migration_status == STATUS_PASS
                else STATUS_WARN
            ),
        },
        {
            "title": "고전 암호 탐지 (Semgrep)",
            "desc": f"레거시 암호 패턴 탐지 — {findings_count}건",
            "status": (
                STATUS_PASS
                if crypto_findings is not None and findings_count == 0
                else (STATUS_WARN if findings_count > 0 else STATUS_UNKNOWN)
            ),
        },
        {
            "title": "정적 보안 분석 (Trivy · Gitleaks · Semgrep)",
            "desc": f"Trivy={trivy} · Gitleaks={gitleaks} · Semgrep={semgrep}",
            "status": overall_scan if scan_ok else STATUS_UNKNOWN,
        },
        {
            "title": "TLS 정책 정적 검증",
            "desc": "nginx.conf 암호 스위트/프로토콜 정책 준수 여부",
            # 후속 동적 검증이 성공이면 정책 검증도 통과했다고 추론
            "status": STATUS_PASS if tls_result == STATUS_PASS else STATUS_UNKNOWN,
        },
        {
            "title": "Docker Build & Up (OQS Nginx)",
            "desc": "PQC 지원 Nginx 컨테이너 빌드 및 기동",
            # 동적 TLS 검증이 이뤄졌다는 것 자체가 컨테이너 기동의 증거
            "status": (
                STATUS_PASS
                if tls_result in (STATUS_PASS, STATUS_FAIL)
                else STATUS_UNKNOWN
            ),
        },
        {
            "title": "TLS 동적 검증",
            "desc": "실제 TLS 협상 & 키교환 그룹 확인",
            "status": tls_result,
        },
        {
            "title": "CBOM 생성 & 비교",
            "desc": "CycloneDX CBOM 생성 및 이전 버전 대비 진척도 비교",
            "status": STATUS_PASS if cbom_present else STATUS_UNKNOWN,
        },
    ]
    return steps


# ---------------------------------------------------------------------------
# 상단 요약 카드 데이터 생성
# ---------------------------------------------------------------------------
def build_summary_cards(
    stage: str,
    run_number: str,
    scan_summary: dict | None,
    crypto_findings: dict | None,
    tls_summary: dict | None,
    cbom: dict | None,
) -> dict:
    tools = (scan_summary or {}).get("tools") or {}
    findings_list = (crypto_findings or {}).get("results") or []
    findings_count = len(findings_list) if isinstance(findings_list, list) else 0

    mig_progress = get_cbom_property(cbom, "securecapstone:migration_progress")
    mig_summary = get_cbom_property(cbom, "securecapstone:migration_summary")

    progress_status = "N/A"
    if isinstance(mig_progress, dict):
        progress_status = str(mig_progress.get("status") or "N/A")

    manual_required: Any = "N/A"
    if isinstance(mig_summary, dict):
        manual_required = mig_summary.get("manual_action_required", "N/A")

    overall = normalize_status((scan_summary or {}).get("overall"))
    if findings_count > 0 and overall == STATUS_PASS:
        overall = STATUS_WARN  # 레거시 암호가 남아있으면 주의 상태로 강조

    return {
        "stage": stage,
        "run_number": run_number,
        "overall": overall,
        "trivy": normalize_status(tools.get("trivy")),
        "gitleaks": normalize_status(tools.get("gitleaks")),
        "semgrep": normalize_status(tools.get("semgrep")),
        "tls": normalize_status((tls_summary or {}).get("result")),
        "findings_count": findings_count,
        "migration_progress": progress_status,
        "manual_required": manual_required,
    }


# ---------------------------------------------------------------------------
# HTML 렌더링 (f-string + html.escape 로 안전하게)
# ---------------------------------------------------------------------------
def esc(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def render_status_badge(status: str, label: str | None = None) -> str:
    text = label if label is not None else status_label_ko(status)
    return (
        f'<span class="badge badge-{esc(status)}">'
        f"{status_icon(status)} {esc(text)}</span>"
    )


def render_summary_cards(s: dict) -> str:
    cards = [
        ("Stage", f"Stage {esc(s['stage'])}", "🧩"),
        ("Run #", f"#{esc(s['run_number'])}", "🏷️"),
        (
            "전체 결과",
            render_status_badge(s["overall"]),
            "📊",
        ),
        ("Trivy (CVE)", render_status_badge(s["trivy"]), "🛡️"),
        ("Gitleaks (Secrets)", render_status_badge(s["gitleaks"]), "🔑"),
        ("Semgrep (SAST)", render_status_badge(s["semgrep"]), "🧪"),
        ("TLS 동적 검증", render_status_badge(s["tls"]), "🔐"),
        ("레거시 암호 탐지", f"{esc(s['findings_count'])}건", "⚠️"),
        ("CBOM 마이그레이션", esc(s["migration_progress"]), "📈"),
        ("수동 조치 필요", f"{esc(s['manual_required'])}건", "🛠️"),
    ]
    items = []
    for title, value, icon in cards:
        items.append(
            f"""
            <div class="card">
              <div class="card-icon">{icon}</div>
              <div class="card-title">{esc(title)}</div>
              <div class="card-value">{value}</div>
            </div>
            """
        )
    return f'<section class="cards-grid">{"".join(items)}</section>'


def render_timeline(steps: list[dict]) -> str:
    items = []
    for i, step in enumerate(steps, start=1):
        status = step["status"]
        items.append(
            f"""
            <li class="tl-item tl-{esc(status)}">
              <div class="tl-marker">{status_icon(status)}</div>
              <div class="tl-body">
                <div class="tl-head">
                  <span class="tl-num">{i:02d}</span>
                  <span class="tl-title">{esc(step['title'])}</span>
                  {render_status_badge(status)}
                </div>
                <div class="tl-desc">{esc(step['desc'])}</div>
              </div>
            </li>
            """
        )
    return f"""
    <section class="panel">
      <h2>📍 파이프라인 진행 순서</h2>
      <ol class="timeline">{"".join(items)}</ol>
    </section>
    """


def render_findings_table(crypto_findings: dict | None) -> str:
    results = (crypto_findings or {}).get("results") or []
    if not isinstance(results, list) or len(results) == 0:
        return """
        <section class="panel">
          <h2>🔍 고전 암호 탐지 결과</h2>
          <div class="empty">✅ 탐지된 레거시 암호가 없습니다.</div>
        </section>
        """

    rows = []
    for r in results:
        if not isinstance(r, dict):
            continue
        path = r.get("path", "")
        line = (r.get("start") or {}).get("line", "")
        rule = r.get("check_id", "")
        extra = r.get("extra") or {}
        sev_raw = str(extra.get("severity", "")).lower()
        sev_status = (
            STATUS_FAIL
            if sev_raw in ("error", "critical", "high")
            else STATUS_WARN
            if sev_raw in ("warning", "medium", "info")
            else STATUS_UNKNOWN
        )
        msg = extra.get("message", "")
        rows.append(
            f"""
            <tr>
              <td class="mono">{esc(path)}:{esc(line)}</td>
              <td class="mono">{esc(rule)}</td>
              <td>{render_status_badge(sev_status, extra.get("severity") or "-")}</td>
              <td>{esc(msg)}</td>
            </tr>
            """
        )

    return f"""
    <section class="panel">
      <h2>🔍 고전 암호 탐지 결과 ({len(results)}건)</h2>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr><th>파일:라인</th><th>Rule</th><th>Severity</th><th>메시지</th></tr>
          </thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
    </section>
    """


def render_tls_section(tls_summary: dict | None) -> str:
    if not isinstance(tls_summary, dict):
        return """
        <section class="panel">
          <h2>🔐 TLS 동적 검증</h2>
          <div class="empty">데이터 없음 — tls-check-summary.json 파일이 없습니다.</div>
        </section>
        """
    neg = tls_summary.get("negotiated") or {}
    status = normalize_status(tls_summary.get("result"))

    def kv(k: str, v: Any) -> str:
        return f'<div class="kv"><span class="k">{esc(k)}</span><span class="v mono">{esc(v or "-")}</span></div>'

    return f"""
    <section class="panel">
      <h2>🔐 TLS 동적 검증 결과</h2>
      <div class="kv-grid">
        {kv("결과", status_label_ko(status))}
        {kv("Stage", tls_summary.get("stage"))}
        {kv("대상", tls_summary.get("target"))}
        {kv("프로토콜", neg.get("protocol"))}
        {kv("Cipher", neg.get("cipher"))}
        {kv("Key Exchange Group", neg.get("group"))}
        {kv("실패 사유", tls_summary.get("fail_reason") or "없음")}
      </div>
    </section>
    """


def render_cbom_section(cbom: dict | None) -> str:
    if not isinstance(cbom, dict):
        return """
        <section class="panel">
          <h2>📦 CBOM 마이그레이션 현황</h2>
          <div class="empty">데이터 없음 — cbom_stage*.json 파일이 없습니다.</div>
        </section>
        """

    progress = get_cbom_property(cbom, "securecapstone:migration_progress")
    summary = get_cbom_property(cbom, "securecapstone:migration_summary")
    findings = get_cbom_property(cbom, "securecapstone:classical_crypto_findings")

    def render_dict(d: Any) -> str:
        if not isinstance(d, dict):
            return f'<div class="mono small">{esc(d)}</div>'
        items = "".join(
            f'<div class="kv"><span class="k">{esc(k)}</span>'
            f'<span class="v mono">{esc(v)}</span></div>'
            for k, v in d.items()
        )
        return f'<div class="kv-grid">{items}</div>'

    findings_block = ""
    if isinstance(findings, list) and findings:
        findings_block = f"""
        <h3>수동 조치 필요 항목 ({len(findings)}건)</h3>
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>파일</th><th>라인</th><th>Rule</th><th>Severity</th><th>조치</th></tr></thead>
            <tbody>
              {"".join(
                f"<tr><td class='mono'>{esc(x.get('file'))}</td>"
                f"<td class='mono'>{esc(x.get('line'))}</td>"
                f"<td class='mono'>{esc(x.get('rule'))}</td>"
                f"<td>{esc(x.get('severity'))}</td>"
                f"<td>{esc(x.get('action_required'))}</td></tr>"
                for x in findings if isinstance(x, dict)
              )}
            </tbody>
          </table>
        </div>
        """

    return f"""
    <section class="panel">
      <h2>📦 CBOM 마이그레이션 현황</h2>
      <h3>Migration Progress</h3>
      {render_dict(progress) if progress else '<div class="empty">progress 데이터 없음</div>'}
      <h3>Migration Summary</h3>
      {render_dict(summary) if summary else '<div class="empty">summary 데이터 없음</div>'}
      {findings_block}
    </section>
    """


def render_raw_json_section(title: str, data: Any) -> str:
    if data is None:
        body = "데이터 없음"
    else:
        try:
            body = json.dumps(data, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            body = str(data)
    return f"""
    <details class="raw">
      <summary>📄 {esc(title)}</summary>
      <pre>{esc(body)}</pre>
    </details>
    """


# ---------------------------------------------------------------------------
# 메인 HTML 조립
# ---------------------------------------------------------------------------
CSS = """
:root {
  --bg: #0b0f17;
  --bg-2: #111827;
  --panel: #151b26;
  --panel-2: #1b2230;
  --border: #232b3d;
  --text: #e6edf7;
  --text-dim: #9aa6bd;
  --accent: #6ea8fe;
  --green: #22c55e;
  --red: #ef4444;
  --yellow: #eab308;
  --gray: #6b7280;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans KR",
    "Apple SD Gothic Neo", "Malgun Gothic", Roboto, sans-serif;
  font-size: 14px; line-height: 1.55; }
.container { max-width: 1180px; margin: 0 auto; padding: 32px 24px 60px; }

header.hero {
  background: linear-gradient(135deg, #141b2b 0%, #1a2338 100%);
  border: 1px solid var(--border); border-radius: 14px;
  padding: 28px 32px; margin-bottom: 28px;
}
header.hero h1 { margin: 0 0 6px; font-size: 22px; letter-spacing: -0.01em; }
header.hero .subtitle { color: var(--text-dim); font-size: 13px; }
header.hero .meta { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 10px; }
header.hero .meta .chip {
  background: var(--panel-2); border: 1px solid var(--border);
  padding: 5px 12px; border-radius: 999px; font-size: 12px; color: var(--text-dim);
}

.cards-grid {
  display: grid; gap: 14px;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  margin-bottom: 28px;
}
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px 18px;
  transition: transform .15s ease, border-color .15s ease;
}
.card:hover { transform: translateY(-1px); border-color: #2f3a55; }
.card-icon { font-size: 18px; margin-bottom: 6px; }
.card-title { color: var(--text-dim); font-size: 12px; margin-bottom: 6px;
  text-transform: uppercase; letter-spacing: .05em; }
.card-value { font-size: 18px; font-weight: 600; }

.badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600;
  border: 1px solid transparent;
}
.badge-success { background: rgba(34,197,94,.12); color: #4ade80; border-color: rgba(34,197,94,.35); }
.badge-fail    { background: rgba(239,68,68,.12); color: #f87171; border-color: rgba(239,68,68,.35); }
.badge-warning { background: rgba(234,179,8,.12); color: #facc15; border-color: rgba(234,179,8,.35); }
.badge-unknown { background: rgba(107,114,128,.15); color: #9ca3af; border-color: rgba(107,114,128,.35); }

.panel {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 14px; padding: 22px 24px; margin-bottom: 22px;
}
.panel h2 { margin: 0 0 18px; font-size: 16px; letter-spacing: -0.01em; }
.panel h3 { margin: 20px 0 10px; font-size: 13px; color: var(--text-dim);
  text-transform: uppercase; letter-spacing: .06em; }

/* Timeline */
.timeline { list-style: none; margin: 0; padding: 0; position: relative; }
.timeline::before {
  content: ""; position: absolute; left: 17px; top: 6px; bottom: 6px;
  width: 2px; background: var(--border);
}
.tl-item { position: relative; padding: 10px 0 10px 48px; }
.tl-marker {
  position: absolute; left: 0; top: 8px; width: 36px; height: 36px;
  border-radius: 50%; background: var(--panel-2); border: 2px solid var(--border);
  display: flex; align-items: center; justify-content: center; font-size: 16px; z-index: 1;
}
.tl-success .tl-marker { border-color: rgba(34,197,94,.6); }
.tl-fail    .tl-marker { border-color: rgba(239,68,68,.6); }
.tl-warning .tl-marker { border-color: rgba(234,179,8,.6); }
.tl-unknown .tl-marker { border-color: rgba(107,114,128,.5); }
.tl-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.tl-num { color: var(--text-dim); font-family: ui-monospace, Menlo, monospace; font-size: 12px; }
.tl-title { font-weight: 600; }
.tl-desc { color: var(--text-dim); font-size: 12.5px; margin-top: 3px; }

/* Tables */
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }
.data-table { width: 100%; border-collapse: collapse; }
.data-table th, .data-table td {
  padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border);
  font-size: 12.5px; vertical-align: top;
}
.data-table th { background: var(--panel-2); color: var(--text-dim);
  font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .04em; }
.data-table tr:last-child td { border-bottom: none; }

/* Key-value grid */
.kv-grid { display: grid; gap: 8px;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); }
.kv { display: flex; justify-content: space-between; gap: 12px;
  background: var(--panel-2); border: 1px solid var(--border);
  border-radius: 8px; padding: 10px 14px; }
.kv .k { color: var(--text-dim); font-size: 12px; }
.kv .v { font-size: 12.5px; word-break: break-all; text-align: right; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.small { font-size: 12px; }
.empty { color: var(--text-dim); font-size: 13px; padding: 8px 2px; }

/* Raw JSON */
details.raw { margin: 10px 0; background: var(--panel);
  border: 1px solid var(--border); border-radius: 10px; padding: 0 16px; }
details.raw summary { cursor: pointer; padding: 12px 0; font-weight: 600; color: var(--text-dim); }
details.raw pre {
  background: #0a0e16; border: 1px solid var(--border); border-radius: 8px;
  padding: 14px; margin: 0 0 14px; overflow: auto; font-size: 12px;
  max-height: 380px;
}

footer { color: var(--text-dim); font-size: 12px; text-align: center; margin-top: 30px; }

@media (max-width: 640px) {
  .container { padding: 20px 14px 40px; }
  header.hero { padding: 22px 20px; }
  .panel { padding: 18px; }
}
"""


def render_html(
    stage: str,
    run_number: str,
    summary_cards_data: dict,
    timeline: list[dict],
    scan_summary: Any,
    crypto_findings: Any,
    tls_summary: Any,
    cbom: Any,
) -> str:
    generated_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overall = summary_cards_data["overall"]

    body = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC Pipeline Dashboard — Stage {esc(stage)} · Run #{esc(run_number)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">

  <header class="hero">
    <h1>🔐 DevSecOps PQC Pipeline Dashboard</h1>
    <div class="subtitle">
      GitHub Actions 파이프라인 실행 결과 요약 &nbsp;·&nbsp; Stage {esc(stage)}
    </div>
    <div class="meta">
      <span class="chip">Run #{esc(run_number)}</span>
      <span class="chip">생성 시각: {esc(generated_at)}</span>
      <span class="chip">전체 결과: {status_icon(overall)} {esc(status_label_ko(overall))}</span>
    </div>
  </header>

  {render_summary_cards(summary_cards_data)}

  {render_timeline(timeline)}

  {render_tls_section(tls_summary)}

  {render_findings_table(crypto_findings)}

  {render_cbom_section(cbom)}

  <section class="panel">
    <h2>📄 원본 JSON (Raw)</h2>
    {render_raw_json_section("scan-summary.json", scan_summary)}
    {render_raw_json_section("tls-check-summary.json", tls_summary)}
    {render_raw_json_section("crypto-findings.json", crypto_findings)}
    {render_raw_json_section(f"cbom_stage{stage}.json", cbom)}
  </section>

  <footer>
    🤖 Generated by dashboard/generate_report.py · self-contained HTML report
  </footer>
</div>
</body>
</html>
"""
    return body


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="DevSecOps PQC Pipeline HTML 대시보드 리포트 생성기",
    )
    p.add_argument("--stage", default="?", help="파이프라인 Stage (1/2/3)")
    p.add_argument("--run-number", default="0", help="GitHub Actions Run 번호")
    p.add_argument(
        "--out",
        default="artifacts/pipeline-dashboard.html",
        help="출력 HTML 파일 경로",
    )
    # 입력 경로는 기본값 사용, 필요 시 override 가능
    p.add_argument("--scan-summary", default="artifacts/scan-summary.json")
    p.add_argument("--crypto-findings", default="artifacts/crypto-findings.json")
    p.add_argument("--tls-summary", default="scanner/results/tls-check-summary.json")
    p.add_argument(
        "--cbom",
        default=None,
        help="CBOM 파일 경로. 미지정 시 artifacts/cbom_stage{stage}.json 사용",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    stage = str(args.stage)
    run_number = str(args.run_number)

    cbom_path = args.cbom or f"artifacts/cbom_stage{stage}.json"

    scan_summary = load_json(args.scan_summary)
    crypto_findings = load_json(args.crypto_findings)
    tls_summary = load_json(args.tls_summary)
    cbom = load_json(cbom_path)

    cards = build_summary_cards(
        stage, run_number, scan_summary, crypto_findings, tls_summary, cbom
    )
    timeline = build_timeline(scan_summary, crypto_findings, tls_summary, cbom)

    html_text = render_html(
        stage=stage,
        run_number=run_number,
        summary_cards_data=cards,
        timeline=timeline,
        scan_summary=scan_summary,
        crypto_findings=crypto_findings,
        tls_summary=tls_summary,
        cbom=cbom,
    )

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html_text)

    print(f"[OK] HTML 대시보드 생성 완료 → {args.out}")
    print(f"     Stage={stage}, Run=#{run_number}, 전체 결과={cards['overall']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
