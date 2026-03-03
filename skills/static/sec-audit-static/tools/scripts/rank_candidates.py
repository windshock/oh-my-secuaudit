#!/usr/bin/env python3
"""
Rank findings/candidates using a simple heuristic:
score = severity_weight + sink_class_weight + boundary_weight + (external input bonus) - path_depth_hint
Outputs sorted list.
"""
import argparse, json
from pathlib import Path

SEVERITY_W = {"Critical":5,"High":4,"Medium":3,"Low":2,"Info":1}
SINK_W = {"exec":3,"eval":3,"sql":3,"net":2,"fs":2,"deserialize":3,"unknown_sink_class":1}
BOUND_W = {"external":2,"network":2,"file":1,"deserialization":2,"unknown_boundary":0}

def score(f):
    sev = SEVERITY_W.get(f.get("severity"),0)
    sink = SINK_W.get(f.get("sink_class"),0)
    bnd = BOUND_W.get(f.get("boundary"),0)
    depth = f.get("path_depth_hint") or 0
    ext = 1 if f.get("boundary") in ("external","network") else 0
    return sev + sink + bnd + ext - float(depth)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()
    rows=[]
    for fp in args.files:
        data=json.load(open(fp))
        for f in data.get("findings",[]):
            f["rank_score"]=score(f)
            rows.append((f["rank_score"], f.get("id"), f.get("title"), fp))
        json.dump(data, open(fp,"w"), ensure_ascii=False, indent=2)
    for s,i,t,fp in sorted(rows, reverse=True):
        print(f"{s:.1f}\t{i}\t{fp}\t{t}")

if __name__=="__main__":
    main()
