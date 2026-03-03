#!/usr/bin/env python3
"""
Apply edge_source/confidence to findings JSONs (bulk).
Usage:
  python edge_confidence_apply.py state/task_*_result.json --edge-source snapshot --confidence 0.9
"""
import argparse, json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--edge-source", required=True)
    ap.add_argument("--confidence", type=float, required=True)
    ap.add_argument("--match-file", help="apply only when finding location file matches substring")
    args = ap.parse_args()
    for path_str in args.files:
        p = Path(path_str)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        changed=False
        for f in data.get("findings", []):
            if isinstance(f, dict):
                locfile = f.get("location",{}).get("file","") or f.get("evidence",{}).get("file","")
                if args.match_file and args.match_file not in locfile:
                    continue
                f["edge_source"] = args.edge_source
                f["confidence"] = args.confidence
                changed=True
        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"edge applied: {p}")

if __name__ == "__main__":
    main()
