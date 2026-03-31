#!/usr/bin/env python3
"""
llm_suggest.py — Gemini API 기반 PQC 마이그레이션 제안 생성

crypto-findings.json의 레거시 암호 탐지 결과를 바탕으로
Gemini API를 호출하여 PQC 대체 코드 제안을 마크다운으로 생성합니다.

Usage:
  python policy/llm_suggest.py --findings <path> --out <path>

Environment:
  GEMINI_API_KEY: Gemini API 키 (필수)
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error


GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash:generateContent?key={api_key}"
)


def read_code_context(file_path, line, context=5):
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        return "".join(lines[start:end]).strip()
    except (FileNotFoundError, IndexError):
        return "(코드를 읽을 수 없습니다)"


def call_gemini(api_key, prompt, retries=3, wait=60):
    url = GEMINI_URL.format(api_key=api_key)
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 1024, "temperature": 0.1},
    }).encode("utf-8")

    for attempt in range(1, retries + 1):
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["candidates"][0]["content"]["parts"][0]["text"]
        except urllib.error.HTTPError as e:
            body_msg = e.read().decode("utf-8", errors="replace")
            print(f"  [DEBUG] HTTP {e.code}: {body_msg[:500]}")
            if e.code == 429 and attempt < retries:
                print(f"  [WARN] Rate limit — {wait}초 후 재시도 ({attempt}/{retries})")
                time.sleep(wait)
            else:
                raise


def generate_suggestions_batch(api_key, results):
    """모든 findings를 단일 API 호출로 처리"""
    items = []
    for i, r in enumerate(results, 1):
        code_context = read_code_context(r["path"], r["start"]["line"])
        items.append(
            f"[{i}] File: {r['path']} Line: {r['start']['line']}\n"
            f"Rule: {r['check_id']} — {r['extra']['message']}\n"
            f"Code:\n```\n{code_context}\n```"
        )

    findings_text = "\n\n".join(items)

    prompt = f"""You are a Post-Quantum Cryptography (PQC) migration expert.

The following legacy cryptography usages were detected:

{findings_text}

For each finding, provide a concise PQC migration suggestion in Korean:
1. 문제 설명 (1문장)
2. 권장 PQC 대안 (ML-KEM FIPS 203 for key exchange, ML-DSA FIPS 204 for signatures)
3. 대체 코드 예시 (코드는 영어로)

Format each response as:
### [{{number}}] <rule_id>
<suggestion>

Keep each suggestion concise and practical."""

    return call_gemini(api_key, prompt)


def main():
    parser = argparse.ArgumentParser(description="Gemini API 기반 PQC 마이그레이션 제안")
    parser.add_argument("--findings", required=True, help="crypto-findings.json 경로")
    parser.add_argument("--out", required=True, help="출력 마크다운 경로")
    args = parser.parse_args()

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY 환경변수가 설정되지 않았습니다.", file=sys.stderr)
        sys.exit(1)

    # 디버그: 사용 가능한 모델 목록 출력
    try:
        list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        with urllib.request.urlopen(list_url, timeout=10) as r:
            models = json.loads(r.read())
            names = [m["name"] for m in models.get("models", [])]
            print(f"[DEBUG] 사용 가능한 모델: {names[:5]}")
    except Exception as e:
        print(f"[DEBUG] 모델 목록 조회 실패: {e}")

    try:
        with open(args.findings, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[INFO] findings 파일 없음 — 제안 생성 건너뜀")
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("## 🤖 LLM PQC 마이그레이션 제안\n\n탐지된 레거시 암호 사용 없음.\n")
        return

    results = data.get("results", [])
    if not results:
        print("[OK] 레거시 암호 탐지 없음 — 제안 불필요")
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("## 🤖 LLM PQC 마이그레이션 제안\n\n탐지된 레거시 암호 사용 없음.\n")
        return

    print(f"[INFO] {len(results)}건 탐지 — Gemini API 단일 배치 호출 중...")

    try:
        batch_response = generate_suggestions_batch(api_key, results)
    except Exception as e:
        print(f"  [WARN] API 호출 실패: {e}")
        batch_response = f"API 호출 실패: {e}"

    # 마크다운 생성
    md = ["## 🤖 LLM PQC 마이그레이션 제안\n"]
    md.append(
        f"> Gemini API가 탐지된 레거시 암호 **{len(results)}건**에 대한 "
        f"PQC 마이그레이션 방법을 제안합니다.\n"
        f"> 제안 내용을 검토 후 적용하세요. (Human-in-the-loop)\n"
    )
    md.append(batch_response)
    md.append("\n---")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"[DONE] 제안 생성 완료 → {args.out}")


if __name__ == "__main__":
    main()
