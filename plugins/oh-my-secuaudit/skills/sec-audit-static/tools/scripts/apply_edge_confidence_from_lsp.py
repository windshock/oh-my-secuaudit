#!/usr/bin/env python3
"""
Apply edge_source/confidence from LSP edge export (TSV/CSV).
Expected columns: file, line (optional), confidence (optional).
Usage:
  python apply_edge_confidence_from_lsp.py lsp_edges.tsv state/task_25_result.json
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
            if not file:
                continue
            conf = row.get("confidence") or row.get("score") or "0.7"
            try:
                conf = float(conf)
            except Exception:
                conf = 0.7
            key = (file, line)
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
            for (fname, lnum), conf in scores.items():
                if fname and fname in locfile:
                    if lnum and locline and lnum != locline:
                        continue
                    f["edge_source"]="lsp"
                    f["confidence"]=conf
                    changed=True
                    break
        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"edge applied from LSP: {p}")

if __name__ == "__main__":
    main()
