#!/usr/bin/env python3
"""ai-migration/migrate.py — AI-assisted PQC migration of legacy crypto findings.

Reads semgrep crypto-classical findings, asks an LLM (GitHub Models)
to rewrite the affected Python file using PQC primitives (ML-KEM / ML-DSA),
applies the changes to a new branch, and opens a pull request.

PoC scope:
- Python files only
- RSA usage findings only (`python-rsa-usage`, `generic-rsa-key-size-weak`)
- Maximum 3 files per run

Environment:
- GITHUB_TOKEN: required, with `models:read` and `repo` scopes
- GITHUB_REPOSITORY: e.g. "owner/repo" (auto-set by GitHub Actions)

Exit codes:
- 0: success (PR created or no findings to migrate)
- 1: configuration error (missing token, missing findings file)
- 2: LLM call failure for all findings
- 3: PR creation failed
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GITHUB_MODELS_ENDPOINT = "https://models.inference.ai.azure.com/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"
MAX_FINDINGS = 3
TARGET_RULE_IDS = {
    "python-rsa-usage",
    "python-rsa-keygen",
    "generic-rsa-key-size-weak",
}


def log(msg: str) -> None:
    print(f"[ai-migration] {msg}", flush=True)


def fail(msg: str, code: int = 1) -> None:
    print(f"[ai-migration][ERROR] {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def load_findings(path: Path) -> list[dict]:
    """Load semgrep findings JSON and filter to migration targets."""
    if not path.exists():
        fail(f"findings file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data.get("results", [])
    targets: list[dict] = []
    for r in results:
        check = r.get("check_id", "")
        rule_id = check.rsplit(".", 1)[-1]
        if rule_id not in TARGET_RULE_IDS:
            continue
        path_ = r.get("path", "")
        if not path_.endswith(".py"):
            continue
        targets.append(r)
    return targets


def group_by_file(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by file path, preserving order, capped at MAX_FINDINGS files."""
    groups: dict[str, list[dict]] = {}
    for f in findings:
        path = f["path"]
        groups.setdefault(path, []).append(f)
        if len(groups) >= MAX_FINDINGS:
            break
    return groups


def render_findings(findings: list[dict]) -> str:
    """Format findings for inclusion in the LLM prompt."""
    lines = []
    for f in findings:
        rule = f.get("check_id", "?").rsplit(".", 1)[-1]
        line_no = f.get("start", {}).get("line", "?")
        msg = f.get("extra", {}).get("message", "").strip()
        lines.append(f"- {rule} at line {line_no}: {msg}")
    return "\n".join(lines)


def build_prompt(template: str, file_content: str, findings: list[dict]) -> str:
    return template.format(
        file_content=file_content,
        findings=render_findings(findings),
    )


def call_github_models(prompt: str, token: str, model: str) -> str | None:
    """Call GitHub Models chat completions API. Returns response text or None on failure."""
    body = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
    }
    req = urllib.request.Request(
        GITHUB_MODELS_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        log(f"HTTPError {e.code}: {body}")
        return None
    except urllib.error.URLError as e:
        log(f"URLError: {e}")
        return None
    except Exception as e:
        log(f"unexpected error: {e}")
        return None

    choices = payload.get("choices", [])
    if not choices:
        log(f"no choices in response: {payload}")
        return None
    content = choices[0].get("message", {}).get("content", "")
    return content.strip() if content else None


def strip_code_fence(text: str) -> str:
    """Strip ```python or ``` fences if the model added them despite instructions."""
    t = text.strip()
    if t.startswith("```"):
        first_newline = t.find("\n")
        if first_newline != -1:
            t = t[first_newline + 1:]
        if t.endswith("```"):
            t = t[:-3]
    return t.strip() + "\n"


def is_valid_python(source: str) -> tuple[bool, str]:
    """Compile-check the migrated source."""
    try:
        compile(source, "<migrated>", "exec")
        return True, ""
    except SyntaxError as e:
        return False, f"line {e.lineno}: {e.msg}"


def run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def short_sha() -> str:
    r = run_git(["rev-parse", "--short", "HEAD"])
    return r.stdout.strip() if r.returncode == 0 else "nosha"


def setup_branch(branch: str) -> bool:
    """Create a new branch from current HEAD."""
    run_git(["config", "user.name", "PQC AI Migration Bot"])
    run_git(["config", "user.email", "pqc-ai-bot@github-actions.com"])
    r = run_git(["checkout", "-b", branch])
    if r.returncode != 0:
        log(f"checkout -b failed: {r.stderr.strip()}")
        return False
    return True


def commit_and_push(branch: str, files: list[str], message: str) -> bool:
    add = run_git(["add", *files])
    if add.returncode != 0:
        log(f"git add failed: {add.stderr.strip()}")
        return False
    diff = run_git(["diff", "--cached", "--quiet"])
    if diff.returncode == 0:
        log("no staged changes — skipping commit")
        return False
    commit = run_git(["commit", "-m", message])
    if commit.returncode != 0:
        log(f"git commit failed: {commit.stderr.strip()}")
        return False
    push = run_git(["push", "-u", "origin", branch])
    if push.returncode != 0:
        log(f"git push failed: {push.stderr.strip()}")
        return False
    return True


def open_pr(branch: str, base: str, title: str, body: str) -> bool:
    r = subprocess.run(
        ["gh", "pr", "create", "--base", base, "--head", branch,
         "--title", title, "--body", body, "--label", "ai-generated"],
        capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        # Fallback: drop label flag (label may not exist)
        log(f"gh pr create with label failed: {r.stderr.strip()}; retrying without label")
        r = subprocess.run(
            ["gh", "pr", "create", "--base", base, "--head", branch,
             "--title", title, "--body", body],
            capture_output=True, text=True, check=False,
        )
    if r.returncode != 0:
        log(f"gh pr create failed: {r.stderr.strip()}")
        return False
    log(f"PR opened: {r.stdout.strip()}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-assisted PQC migration")
    parser.add_argument("--findings", default="artifacts/crypto-findings.json",
                        help="semgrep findings JSON path")
    parser.add_argument("--prompt", default="ai-migration/prompts/rsa_to_mlkem.txt",
                        help="prompt template path")
    parser.add_argument("--base", default="develop",
                        help="base branch for the generated PR")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="GitHub Models model name")
    parser.add_argument("--dry-run", action="store_true",
                        help="run LLM and write files, but skip git/PR")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        fail("GITHUB_TOKEN environment variable is required", code=1)

    findings_path = Path(args.findings)
    prompt_path = Path(args.prompt)
    if not prompt_path.exists():
        fail(f"prompt template not found: {prompt_path}")

    findings = load_findings(findings_path)
    if not findings:
        log("no migration-target findings — exiting cleanly")
        return 0

    grouped = group_by_file(findings)
    log(f"found {sum(len(v) for v in grouped.values())} findings in "
        f"{len(grouped)} file(s) (cap: {MAX_FINDINGS})")

    template = prompt_path.read_text(encoding="utf-8")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"auto-migration/{short_sha()}-{timestamp}"

    rewrites: dict[str, str] = {}
    failures: list[str] = []

    for path, file_findings in grouped.items():
        log(f"processing {path} ({len(file_findings)} finding(s))")
        try:
            content = Path(path).read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError) as e:
            log(f"  cannot read file: {e}")
            failures.append(path)
            continue

        prompt = build_prompt(template, content, file_findings)
        response = call_github_models(prompt, token, args.model)
        if response is None:
            log(f"  LLM call failed for {path}")
            failures.append(path)
            continue
        if response.strip() == "NO_MIGRATION_POSSIBLE":
            log(f"  LLM declined: NO_MIGRATION_POSSIBLE")
            failures.append(path)
            continue

        new_content = strip_code_fence(response)
        ok, err = is_valid_python(new_content)
        if not ok:
            log(f"  syntax check failed: {err}")
            failures.append(path)
            continue
        if new_content == content:
            log(f"  LLM returned unchanged content")
            failures.append(path)
            continue

        rewrites[path] = new_content
        log(f"  migration prepared")

    if not rewrites:
        log("no successful migrations — exiting")
        return 2 if failures else 0

    for path, new_content in rewrites.items():
        Path(path).write_text(new_content, encoding="utf-8")
        log(f"wrote {path}")

    if args.dry_run:
        log("dry-run: skipping branch/commit/PR")
        return 0

    if not setup_branch(branch):
        return 3

    files_changed = list(rewrites.keys())
    title = f"chore(ai-migration): RSA → ML-KEM migration ({len(files_changed)} file(s))"
    body_lines = [
        "## 요약",
        "",
        f"AI 보조 PQC 마이그레이션. semgrep `crypto-classical.yaml` 룰이 탐지한 RSA 사용 코드를 ML-KEM(FIPS 203) / ML-DSA(FIPS 204)로 자동 변환했습니다.",
        "",
        "## 변경 파일",
        "",
    ]
    for p in files_changed:
        related = grouped.get(p, [])
        body_lines.append(f"- `{p}` — finding {len(related)}건")
    body_lines.extend([
        "",
        "## 검증 가이드",
        "",
        "1. 변경 diff 검토 — 비기능적 수정이 섞여 있지 않은지 확인",
        "2. import / 의존성 변경 확인 (`oqs-python` 추가 여부)",
        "3. 함수 시그니처 변화 확인 (ML-KEM은 ciphertext + shared_secret 튜플 반환)",
        "4. 단위 테스트 통과 여부 확인",
        "",
        "## 주의 사항",
        "",
        f"- 모델: {args.model} (GitHub Models)",
        f"- 자동 생성된 PR이므로 머지 전 반드시 사람 리뷰 필요",
        f"- 마이그레이션 처리 한도: 최대 {MAX_FINDINGS}개 파일",
    ])
    if failures:
        body_lines.extend([
            "",
            "## 실패한 항목",
            "",
        ])
        for p in failures:
            body_lines.append(f"- `{p}` — LLM 응답 실패 또는 문법 오류")
    body = "\n".join(body_lines)

    commit_msg = f"chore(ai-migration): RSA → ML-KEM 자동 변환 ({len(files_changed)}개 파일)"
    if not commit_and_push(branch, files_changed, commit_msg):
        return 3

    if not open_pr(branch, args.base, title, body):
        return 3

    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
