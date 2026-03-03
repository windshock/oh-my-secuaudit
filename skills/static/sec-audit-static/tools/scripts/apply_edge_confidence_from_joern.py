#!/usr/bin/env python3
"""
Parse Joern TSV (taint results) to assign edge_source/confidence per finding.
Expected TSV columns include 'file' and optionally 'score' or 'confidence'.
Usage:
  python apply_edge_confidence_from_joern.py joern_taint_results.tsv state/task_25_result.json
"""
import csv, json, sys
from pathlib import Path

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    tsv = Path(sys.argv[1])
    files = sys.argv[2:]
    scores = {}
    with tsv.open() as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            file = row.get("file") or row.get("filename") or ""
            line = row.get("line") or row.get("lineno") or ""
            method = row.get("method") or ""
            if not file:
                continue
            conf = row.get("confidence") or row.get("score") or "0.8"
            try:
                conf = float(conf)
            except Exception:
                conf = 0.8
            key = (file, line, method)
            scores[key] = max(scores.get(key, 0), conf)
    for path_str in files:
        p = Path(path_str)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        changed=False
        for f in data.get("findings", []):
            locfile = f.get("location",{}).get("file","") or f.get("evidence",{}).get("file","")
            locline = str(f.get("location",{}).get("line","") or "")
            method = f.get("function") or f.get("method") or ""
            for (fname, lnum, mth), conf in scores.items():
                if fname and fname in locfile:
                    if lnum and locline and lnum != locline:
                        continue
                    if mth and method and mth not in method:
                        continue
                    f["edge_source"]="joern"
                    f["confidence"]=conf
                    changed=True
                    break
        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"edge applied from joern TSV: {p}")

if __name__ == "__main__":
    main()
