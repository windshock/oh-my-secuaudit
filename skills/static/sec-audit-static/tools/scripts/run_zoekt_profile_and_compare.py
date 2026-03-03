#!/usr/bin/env python3
"""Run zoekt-based scan profile and auto-compare with previous outputs.

Default profile is api-max (API coverage-first, practical global scans):
- scan_api.py max-candidates=0
- scan_injection_patterns.py max-candidates=800
- scan_injection_enhanced.py max-candidates=800
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def run_cmd(cmd: list[str], env: dict[str, str]) -> None:
    print("$", " ".join(cmd))
    proc = subprocess.run(cmd, env=env)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_nested(d: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def extract_metrics(api: dict[str, Any], pat: dict[str, Any], enh: dict[str, Any]) -> dict[str, Any]:
    return {
        "api": {
            "total_endpoints": api.get("total_endpoints", 0),
            "total_files_scanned": api.get("total_files_scanned", 0),
            "prefilter_file_count": get_nested(api, ["search_scope", "prefilter_file_count"], 0),
            "function_context_total": get_nested(api, ["function_context", "total_contexts"], 0),
        },
        "patterns": {
            "total_suspicious": get_nested(pat, ["summary", "total_suspicious"], 0),
            "sql_injection_count": get_nested(pat, ["summary", "sql_injection_count"], 0),
            "os_command_injection_count": get_nested(pat, ["summary", "os_command_injection_count"], 0),
            "ssi_injection_count": get_nested(pat, ["summary", "ssi_injection_count"], 0),
            "total_files_scanned": pat.get("total_files_scanned", 0),
            "prefilter_file_count": get_nested(pat, ["search_scope", "prefilter_file_count"], 0),
            "function_context_total": get_nested(pat, ["function_context", "total_contexts"], 0),
        },
        "enhanced": {
            "needs_review": get_nested(enh, ["summary", "needs_review"], 0),
            "os_command_total": get_nested(enh, ["summary", "os_command", "total"], 0),
            "ssi_total": get_nested(enh, ["summary", "ssi", "total"], 0),
            "function_context_total": get_nested(enh, ["function_context", "total_contexts"], 0),
        },
    }


def compare_metrics(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for section, metrics in new.items():
        out[section] = {}
        old_section = old.get(section, {})
        for key, new_value in metrics.items():
            old_value = old_section.get(key, 0)
            try:
                delta = new_value - old_value
                pct = (delta / old_value * 100.0) if old_value else None
            except Exception:
                delta = None
                pct = None
            out[section][key] = {
                "old": old_value,
                "new": new_value,
                "delta": delta,
                "delta_pct": pct,
            }
    return out


def to_md(compare: dict[str, Any], new_paths: dict[str, str], old_paths: dict[str, str]) -> str:
    lines = []
    lines.append("# Zoekt Profile Comparison (api-max)")
    lines.append("")
    lines.append("## Files")
    lines.append(f"- New API: `{new_paths['api']}`")
    lines.append(f"- New patterns: `{new_paths['patterns']}`")
    lines.append(f"- New enhanced: `{new_paths['enhanced']}`")
    lines.append(f"- Old API: `{old_paths['api']}`")
    lines.append(f"- Old patterns: `{old_paths['patterns']}`")
    lines.append(f"- Old enhanced: `{old_paths['enhanced']}`")
    lines.append("")
    for section, metrics in compare.items():
        lines.append(f"## {section}")
        lines.append("| metric | old | new | delta | delta_pct |")
        lines.append("|---|---:|---:|---:|---:|")
        for key, row in metrics.items():
            pct = "-" if row["delta_pct"] is None else f"{row['delta_pct']:.2f}%"
            lines.append(f"| {key} | {row['old']} | {row['new']} | {row['delta']} | {pct} |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run zoekt api-max profile and auto-compare")
    ap.add_argument("source_dir")
    ap.add_argument("--out-dir", default="/tmp")
    ap.add_argument("--name", default="targetsvc_zoekt_api_max")
    ap.add_argument(
        "--compare-prefix",
        default="/tmp/targetsvc_zoekt_api_max_prev",
        help="Previous prefix for auto-compare (expects .api.json/.patterns.json/.enh.json)",
    )
    ap.add_argument("--api-max-candidates", type=int, default=0)
    ap.add_argument("--patterns-max-candidates", type=int, default=800)
    ap.add_argument("--enh-max-candidates", type=int, default=800)
    ap.add_argument(
        "--function-context-python",
        default="",
        help="Python path for extract_function_context.py (tree-sitter venv recommended)",
    )
    args = ap.parse_args()

    source_dir = Path(args.source_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    scripts_dir = Path(__file__).resolve().parent
    api_script = scripts_dir / "scan_api.py"
    pat_script = scripts_dir / "scan_injection_patterns.py"
    enh_script = scripts_dir / "scan_injection_enhanced.py"

    prefix = out_dir / args.name
    api_out = Path(str(prefix) + ".api.json")
    pat_out = Path(str(prefix) + ".patterns.json")
    enh_out = Path(str(prefix) + ".enh.json")
    cmp_json = Path(str(prefix) + ".compare.json")
    cmp_md = Path(str(prefix) + ".compare.md")

    env = os.environ.copy()
    if args.function_context_python:
        env["FUNCTION_CONTEXT_PYTHON"] = args.function_context_python

    # api-max profile (coverage-first)
    run_cmd(
        [
            sys.executable,
            str(api_script),
            str(source_dir),
            "--search-engine",
            "zoekt",
            "--max-candidates",
            str(args.api_max_candidates),
            "--function-context-auto",
            "--function-context-max",
            "40",
            "--function-context-radius",
            "40",
            "--output",
            str(api_out),
            "--quiet",
        ],
        env,
    )

    inj_query = r"executeQuery\(|createQuery\(|prepareStatement\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\(|<!--#exec"

    run_cmd(
        [
            sys.executable,
            str(pat_script),
            str(source_dir),
            "--search-engine",
            "zoekt",
            "--search-query",
            inj_query,
            "--max-candidates",
            str(args.patterns_max_candidates),
            "--function-context-auto",
            "--function-context-max",
            "40",
            "--function-context-radius",
            "40",
            "--output",
            str(pat_out),
            "--quiet",
        ],
        env,
    )

    run_cmd(
        [
            sys.executable,
            str(enh_script),
            str(source_dir),
            "--api-inventory",
            str(api_out),
            "--search-engine",
            "zoekt",
            "--search-query",
            inj_query,
            "--max-candidates",
            str(args.enh_max_candidates),
            "--function-context-auto",
            "--function-context-max",
            "40",
            "--function-context-radius",
            "40",
            "--output",
            str(enh_out),
        ],
        env,
    )

    prev_prefix = Path(args.compare_prefix)
    prev_api = Path(str(prev_prefix) + ".api.json")
    prev_pat = Path(str(prev_prefix) + ".patterns.json")
    prev_enh = Path(str(prev_prefix) + ".enh.json")

    new_paths = {"api": str(api_out), "patterns": str(pat_out), "enhanced": str(enh_out)}
    old_paths = {"api": str(prev_api), "patterns": str(prev_pat), "enhanced": str(prev_enh)}

    new_metrics = extract_metrics(load_json(api_out), load_json(pat_out), load_json(enh_out))

    payload: dict[str, Any] = {
        "profile": "api-max",
        "source_dir": str(source_dir),
        "new_outputs": new_paths,
        "new_metrics": new_metrics,
        "old_outputs": old_paths,
    }

    if prev_api.exists() and prev_pat.exists() and prev_enh.exists():
        old_metrics = extract_metrics(load_json(prev_api), load_json(prev_pat), load_json(prev_enh))
        cmp = compare_metrics(old_metrics, new_metrics)
        payload["old_metrics"] = old_metrics
        payload["comparison"] = cmp
        cmp_md.write_text(to_md(cmp, new_paths, old_paths), encoding="utf-8")
    else:
        payload["comparison"] = "skipped: previous outputs not found"
        cmp_md.write_text(
            "# Zoekt Profile Comparison (api-max)\n\nPrevious outputs not found; comparison skipped.\n",
            encoding="utf-8",
        )

    cmp_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"saved: {api_out}")
    print(f"saved: {pat_out}")
    print(f"saved: {enh_out}")
    print(f"saved: {cmp_json}")
    print(f"saved: {cmp_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
