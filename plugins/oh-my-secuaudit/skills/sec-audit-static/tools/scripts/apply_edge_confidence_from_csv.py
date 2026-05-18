#!/usr/bin/env python3
"""
Apply edge_source/confidence to findings based on CSV mapping.
CSV columns: file,edge_source,confidence
Usage:
  python apply_edge_confidence_from_csv.py mapping.csv state/task_25_result.json
"""
import csv, json, sys
from pathlib import Path

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    csv_path = Path(sys.argv[1])
    files = sys.argv[2:]
    rules=[]
    for row in csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()):
        rules.append({
            "file": row.get("file",""),
            "edge_source": row.get("edge_source",""),
            "confidence": float(row.get("confidence") or 0)
        })
    for path_str in files:
        p = Path(path_str)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        changed=False
        for f in data.get("findings", []):
            locfile = f.get("location",{}).get("file","") or f.get("evidence",{}).get("file","")
            for r in rules:
                if r["file"] in locfile:
                    f["edge_source"]=r["edge_source"]
                    f["confidence"]=r["confidence"]
                    changed=True
                    break
        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"edge applied from CSV: {p}")

if __name__ == "__main__":
    main()
