#!/usr/bin/env python3
"""
Sample and score slice quality for quick post-run QA.

Scoring is heuristic and intentionally simple:
- has line-numbered code rows
- has enough non-empty lines
- not dominated by "truncated" markers
"""

import argparse
import hashlib
import json
from pathlib import Path


def pick_samples(files, sample_rate, min_samples):
    if not files:
        return []
    count = max(min_samples, int(len(files) * sample_rate))
    count = min(count, len(files))
    ranked = sorted(files, key=lambda p: hashlib.sha1(str(p).encode()).hexdigest())
    return ranked[:count]


def score_slice(path: Path):
    txt = path.read_text(encoding="utf-8", errors="ignore")
    lines = txt.splitlines()
    non_empty = [ln for ln in lines if ln.strip()]
    numbered = sum(1 for ln in lines if ":" in ln and ln.strip()[:1].isdigit())
    truncated = sum(1 for ln in lines if "truncated" in ln.lower())

    score = 100
    notes = []
    if len(non_empty) < 20:
        score -= 25
        notes.append("too_short")
    if numbered < 8:
        score -= 30
        notes.append("few_numbered_lines")
    if truncated > max(3, len(lines) // 8):
        score -= 20
        notes.append("many_truncated_markers")
    if score < 0:
        score = 0
    return {
        "file": str(path),
        "line_count": len(lines),
        "non_empty_lines": len(non_empty),
        "numbered_lines": numbered,
        "truncated_markers": truncated,
        "score": score,
        "notes": notes,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--slices-dir", required=True)
    p.add_argument("--sample-rate", type=float, default=0.05)
    p.add_argument("--min-samples", type=int, default=1)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    slices_dir = Path(args.slices_dir)
    files = sorted(slices_dir.glob("*.txt"))
    sampled = pick_samples(files, args.sample_rate, args.min_samples)
    rows = [score_slice(f) for f in sampled]
    avg = round(sum(r["score"] for r in rows) / len(rows), 2) if rows else 0.0

    out = {
        "slices_dir": str(slices_dir),
        "total_slices": len(files),
        "sample_rate": args.sample_rate,
        "sampled_count": len(sampled),
        "average_score": avg,
        "items": rows,
    }
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"written: {args.output}")


if __name__ == "__main__":
    main()
