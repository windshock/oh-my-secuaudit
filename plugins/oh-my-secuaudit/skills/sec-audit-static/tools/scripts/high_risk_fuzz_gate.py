#!/usr/bin/env python3
"""
Select top-K high-risk unknown findings for fuzz/smoke gate.
Criteria: severity >= High OR sink_class in {exec, eval, sql, deserialize}; status/unknown_reason startswith unknown_*
Outputs queue JSON with candidate ids/files.
"""
import argparse, json
from pathlib import Path

def is_high_risk(f):
    sev = f.get("severity","")
    sink = f.get("sink_class","")
    status = f.get("status","")
    unk = f.get("unknown_reason","")
    high_sev = sev in ("Critical","High")
    high_sink = sink in ("exec","eval","sql","deserialize")
    is_unknown = status.startswith("unknown") or (unk and unk.startswith("unknown"))
    return is_unknown and (high_sev or high_sink)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--out", default="fuzz_queue.json")
    args = ap.parse_args()

    queue=[]
    for fp in args.files:
        data=json.load(open(fp))
        for f in data.get("findings",[]):
            if is_high_risk(f):
                queue.append({
                    "id": f.get("id"),
                    "file": f.get("location",{}).get("file"),
                    "status": f.get("status"),
                    "unknown_reason": f.get("unknown_reason"),
                    "severity": f.get("severity"),
                    "sink_class": f.get("sink_class"),
                    "source": fp
                })
    queue=sorted(queue, key=lambda x: (x["severity"], x["sink_class"]), reverse=True)[:args.top_k]
    Path(args.out).write_text(json.dumps(queue, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"fuzz queue written: {args.out} (items={len(queue)})")

if __name__=="__main__":
    main()
