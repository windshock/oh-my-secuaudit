#!/usr/bin/env python3
"""
Translate finding fields to Korean using OpenAI API.

Usage:
  OPENAI_API_KEY=... python tools/scripts/translate_findings_openai.py \
    --in state/task_23_result.json --out state/task_23_result.ko.json \
    --model gpt-4o-mini
"""

import argparse
import json
import os
import sys
import time
import urllib.request


API_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")


def call_openai(messages, model, temperature=0.1, max_tokens=2000):
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing OPENAI_API_KEY")

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{API_URL}/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        raw = resp.read().decode("utf-8")
    res = json.loads(raw)
    return res["choices"][0]["message"]["content"]


def translate_batch(texts, model):
    system = (
        "You are a professional security report translator. "
        "Translate the given strings to Korean. "
        "Keep code blocks, file paths, API paths, identifiers, and inline code as-is. "
        "Do not add commentary. Return ONLY a JSON array of strings in the same order."
    )
    user = json.dumps(texts, ensure_ascii=False)
    content = call_openai(
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        model=model,
    )
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list) and len(parsed) == len(texts):
            return parsed
    except Exception:
        pass
    return texts


def main():
    ap = argparse.ArgumentParser(description="Translate findings JSON fields to Korean (OpenAI API)")
    ap.add_argument("--in", dest="input_path", required=True, help="Input JSON file")
    ap.add_argument("--out", dest="output_path", required=True, help="Output JSON file")
    ap.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))
    ap.add_argument("--sleep", type=float, default=0.0, help="Sleep seconds between API calls")
    args = ap.parse_args()

    with open(args.input_path, encoding="utf-8") as f:
        data = json.load(f)

    fields = ["title", "description", "impact", "recommendation", "remediation"]

    for finding in data.get("findings", []):
        texts = []
        keys = []
        for k in fields:
            v = finding.get(k)
            if isinstance(v, str) and v.strip():
                texts.append(v)
                keys.append(k)

        if not texts:
            continue

        translated = translate_batch(texts, args.model)
        for k, v in zip(keys, translated):
            finding[k] = v

        if args.sleep:
            time.sleep(args.sleep)

    with open(args.output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)
