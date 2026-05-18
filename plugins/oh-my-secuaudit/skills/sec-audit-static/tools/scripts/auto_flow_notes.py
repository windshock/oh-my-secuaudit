#!/usr/bin/env python3
"""
Auto-append attempt evidence into flow/notes for unknown findings.
Adds markers for steps executed (edge/slice/runtime/fuzz/request_mapping).
Usage:
  python auto_flow_notes.py state/task_25_result.json --note "edge:joern planned"
"""
import argparse, json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--note", action="append", default=[], help="marker to append into flow")
    args = ap.parse_args()

    markers = args.note or []
    for path_str in args.files:
        p = Path(path_str)
        data = json.loads(p.read_text(encoding="utf-8"))
        changed=False
        for f in data.get("findings", []):
            if not isinstance(f, dict):
                continue
            status = str(f.get("status",""))
            unk = f.get("unknown_reason")
            if status.startswith("unknown") or unk:
                flow = f.setdefault("flow", [])
                for m in markers:
                    if m not in flow:
                        flow.append(m)
                        changed=True
        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"flow updated: {p}")

if __name__ == "__main__":
    main()
