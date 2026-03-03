#!/usr/bin/env python3
"""
Lightweight context slicer with budget and fallbacks.
Inputs: list of files (JSON findings) or direct source file/line args.
Default budget: 120 lines max, otherwise mark overflow.
Fallback ladder: same-function slice (approx) -> centered slice -> head/tail fallback.
Outputs: writes slices to <state>/slices/<candidate_id>.txt when candidate_id present; otherwise prints to stdout.
"""

import argparse
import json
from pathlib import Path

def slice_file(src: Path, center: int, budget: int = 120, max_budget: int = 200, attempts: int = 0) -> tuple[str, bool, int]:
    lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()
    n = len(lines)
    half = budget // 2
    start = max(1, center - half)
    end = min(n, start + budget - 1)
    start = max(1, end - budget + 1)
    snippet = "\n".join(f"{i+1:5d}: {lines[i]}" for i in range(start-1, end))
    overflow = (end - start + 1) >= budget or start > 1 or end < n
    # auto-tune: if overflow and attempts < 2 and budget < max_budget, try larger budget
    if overflow and attempts < 2 and budget < max_budget:
        new_budget = min(max_budget, budget + 40)
        return slice_file(src, center, new_budget, max_budget, attempts + 1)
    return snippet, overflow, budget

def process_finding(f, root: Path, out_dir: Path, budget: int):
    loc = f.get("location", {}) or f.get("evidence", {})
    rel = loc.get("file")
    line = loc.get("line") or (loc.get("lines") or [None])[0]
    if not rel or not line:
        return False
    src = root / rel
    if not src.exists():
        return False
    snippet, overflow, final_budget = slice_file(src, int(line), budget)
    cid = f.get("id") or f.get("candidate_id") or "unknown"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{cid}.txt").write_text(snippet, encoding="utf-8")
    if overflow and f.get("unknown_reason") is None:
        f["unknown_reason"] = "unknown_context_budget"
    if overflow and "flow" in f:
        f["flow"].append(f"slice overflow -> truncated (budget={final_budget})")
    f["slice_budget_used"] = final_budget
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="finding JSON files")
    ap.add_argument("--repo", required=True, help="repo root for source paths")
    ap.add_argument("--state-dir", required=True, help="state directory for slices output")
    ap.add_argument("--budget", type=int, default=120)
    args = ap.parse_args()

    root = Path(args.repo)
    out_dir = Path(args.state_dir) / "slices"
    changed = 0
    for inp in args.inputs:
        p = Path(inp)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        ok = False
        for f in data.get("findings", []):
            if isinstance(f, dict):
                ok = process_finding(f, root, out_dir, args.budget) or ok
        if ok:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            changed += 1
            print(f"sliced: {p}")
    print(f"done. sliced {changed} files")

if __name__ == "__main__":
    main()
