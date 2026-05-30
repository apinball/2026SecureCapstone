"""GitHub Models API 호출 wrapper. 단일 LLM 호출 책임.

환경 변수: GITHUB_TOKEN (models:read scope 필요).
"""
import json
import os
import time
import urllib.error
import urllib.request

GITHUB_MODELS_ENDPOINT = "https://models.inference.ai.azure.com/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"


def call_llm(prompt: str, model: str = DEFAULT_MODEL, temperature: float = 0.0,
             max_retries: int = 3) -> tuple[str | None, str | None]:
    """반환: (응답 문자열, 에러 메시지). 성공 시 에러 None."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return None, "GITHUB_TOKEN 미설정"

    body = json.dumps({
        "model": model,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        GITHUB_MODELS_ENDPOINT,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    last_err: str | None = None
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = data["choices"][0]["message"]["content"]
            return text, None
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:300]}"
            if e.code in {429, 500, 502, 503, 504}:
                time.sleep(2 ** attempt)
                continue
            break
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            time.sleep(2 ** attempt)

    return None, last_err
