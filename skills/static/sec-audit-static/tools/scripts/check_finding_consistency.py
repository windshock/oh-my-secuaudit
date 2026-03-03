#!/usr/bin/env python3
"""
Task finding consistency checks.

Purpose
- Warn when wording like "without authentication" conflicts with runtime evidence.
- Surface mixed-category task files (informational), so report generators must handle per-finding category.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


AUTH_WORDING_PATTERNS = [
    re.compile(r"\bwithout authentication\b", re.IGNORECASE),
    re.compile(r"\bunauthenticated callers?\b", re.IGNORECASE),
    re.compile(r"인증\s*없이"),
    re.compile(r"무인증"),
]


def _parse_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _has_authless_wording(text: str) -> bool:
    return any(p.search(text or "") for p in AUTH_WORDING_PATTERNS)


def _extract_command(request_mapping: str) -> str | None:
    # Prefer 4-digit command from mapping like /swapp/sw5/5800
    if not request_mapping:
        return None
    m = re.search(r"/(\d{4})(?:$|[/?#])", request_mapping)
    if m:
        return m.group(1)
    return None


def _rtn_code(path: Path) -> str | None:
    if not path.exists():
        return None
    data = _parse_json(path)
    return (
        data.get("ResData", {})
        .get("ResHeader", {})
        .get("rtnCode")
    )


def check_file(task_json: Path, runtime_evidence_dir: Path | None) -> list[str]:
    data = _parse_json(task_json)
    findings = data.get("findings", []) if isinstance(data, dict) else []
    warnings: list[str] = []

    categories = sorted({str(f.get("category", "")).strip() for f in findings if isinstance(f, dict)})
    if len([c for c in categories if c]) > 1:
        warnings.append(
            f"{task_json.name}: mixed categories detected ({', '.join(c for c in categories if c)})"
        )

    if runtime_evidence_dir is None:
        return warnings

    for f in findings:
        if not isinstance(f, dict):
            continue
        text = " ".join(
            [
                str(f.get("title", "")),
                str(f.get("description", "")),
                str(f.get("impact", "")),
            ]
        )
        if not _has_authless_wording(text):
            continue

        cmd = _extract_command(str(f.get("request_mapping", "")))
        if not cmd:
            continue

        without_auth = runtime_evidence_dir / f"resp_{cmd}_without_auth.json"
        with_auth = runtime_evidence_dir / f"resp_{cmd}_with_auth.json"
        code_without = _rtn_code(without_auth)
        code_with = _rtn_code(with_auth)

        if code_without and code_with and code_without != "0000" and code_with == "0000":
            warnings.append(
                f"{task_json.name}:{f.get('id','?')} wording says unauthenticated, "
                f"but runtime shows auth required ({cmd}: without_auth={code_without}, with_auth={code_with})"
            )

    return warnings


def main() -> None:
    p = argparse.ArgumentParser(description="Check finding wording/category consistency")
    p.add_argument("task_json", nargs="+", help="task_*_result.json path(s)")
    p.add_argument("--runtime-evidence-dir", default=None, help="state/runtime_evidence directory")
    p.add_argument("--strict", action="store_true", help="exit non-zero on warning")
    args = p.parse_args()

    runtime_dir = Path(args.runtime_evidence_dir) if args.runtime_evidence_dir else None
    warnings: list[str] = []
    for file_str in args.task_json:
        warnings.extend(check_file(Path(file_str), runtime_dir))

    if warnings:
        print("[consistency] warnings:")
        for w in warnings:
            print(f"  - {w}")
        if args.strict:
            raise SystemExit(1)
    else:
        print("[consistency] no issues")


if __name__ == "__main__":
    main()

