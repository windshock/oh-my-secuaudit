#!/usr/bin/env python3
"""
Merge edge_source/confidence from multiple sources with precedence:
snapshot > lsp > joern > csv > grep existing.
Inputs: finding JSON files; optional mapping files detected automatically:
  - state/joern_taint_results.tsv
  - state/lsp_edges.tsv
  - edge CSV (via --edge-csv)
If a higher-tier edge is found for the same finding (file/line/method match), it overwrites lower-tier.
"""
import argparse, json, csv
from pathlib import Path

TIERS = {"snapshot":4, "lsp":3, "joern":2, "csv":1, "grep":0}

def load_tsv(path: Path, source: str, default_conf: float) -> list[dict]:
    rows=[]
    with path.open() as f:
        reader = csv.DictReader(f, delimiter="\t")
        for r in reader:
            file = r.get("file") or r.get("filename") or ""
            line = r.get("line") or r.get("lineno") or ""
            method = r.get("method") or ""
            if not file:
                continue
            conf = r.get("confidence") or r.get("score") or default_conf
            try: conf = float(conf)
            except Exception: conf = default_conf
            rows.append({"file":file, "line":str(line), "method":method, "source":source, "confidence":conf})
    return rows

def load_csv(path: Path) -> list[dict]:
    rows=[]
    with path.open() as f:
        reader = csv.DictReader(f)
        for r in reader:
            file = r.get("file") or ""
            if not file: continue
            rows.append({"file":file, "line":str(r.get("line") or ""), "method": r.get("method") or "",
                         "source":"csv", "confidence": float(r.get("confidence") or 0.6)})
    return rows

def find_match(row, locfile, locline, method):
    if row["file"] not in locfile:
        return False
    if row["line"] and locline and row["line"] != locline:
        return False
    if row["method"] and method and row["method"] not in method:
        return False
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="finding JSON files")
    ap.add_argument("--state-dir", default="state")
    ap.add_argument("--edge-csv")
    args = ap.parse_args()

    state = Path(args.state_dir)
    sources = []
    if (state/"joern_taint_results.tsv").exists():
        sources += load_tsv(state/"joern_taint_results.tsv", "joern", 0.8)
    if (state/"lsp_edges.tsv").exists():
        sources += load_tsv(state/"lsp_edges.tsv", "lsp", 0.7)
    if args.edge_csv:
        p = Path(args.edge_csv)
        if p.exists():
            sources += load_csv(p)

    for path_str in args.files:
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
            cur_source = f.get("edge_source") or "grep"
            cur_conf = f.get("confidence") or 0
            cur_tier = TIERS.get(cur_source, 0)
            for row in sources:
                if find_match(row, locfile, locline, method):
                    tier = TIERS.get(row["source"],0)
                    if tier > cur_tier or (tier==cur_tier and row["confidence"]>cur_conf):
                        f["edge_source"]=row["source"]
                        f["confidence"]=row["confidence"]
                        cur_tier = tier
                        cur_conf = row["confidence"]
                        changed=True
        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"edge merge applied: {p}")

if __name__ == "__main__":
    main()
