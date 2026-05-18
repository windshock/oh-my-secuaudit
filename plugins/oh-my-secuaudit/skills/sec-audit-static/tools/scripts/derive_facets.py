#!/usr/bin/env python3
"""
Auto-derive facet tags (layer/boundary/sink_class) for findings.

Heuristics:
- layer: controller|resource|endpoint -> controller, service|svc -> service, dao|repository -> dao, util|common -> util
- boundary: if path includes controller/resource/endpoint => external, if file/dfs keywords => file, if deserialize/json/xml => deserialization, else unknown_boundary
- sink_class: sql/mapper/jdbc/jpa => sql, http/rest/template/url/openConnection => net, file/io => fs, eval/exec/processbuilder => exec, unknown_sink_class otherwise
Usage:
  python derive_facets.py state/task_25_result.json [...more files]
"""

import json
import re
import sys
from pathlib import Path

LAYER_PATTERNS = [
    ("controller", re.compile(r"(controller|endpoint|resource)", re.I)),
    ("service", re.compile(r"(service|svc)", re.I)),
    ("dao", re.compile(r"(dao|repository|mapper)", re.I)),
    ("util", re.compile(r"(util|common|helper)", re.I)),
]

BOUNDARY_PATTERNS = [
    ("external", re.compile(r"(controller|endpoint|resource)", re.I)),
    ("file", re.compile(r"(file|fs|io/|nio)", re.I)),
    ("deserialization", re.compile(r"(deserialize|serialization|objectmapper|gson|json|xml)", re.I)),
]

SINK_PATTERNS = [
    ("sql", re.compile(r"(jdbc|jpa|query|mapper|mybatis|sql)", re.I)),
    ("net", re.compile(r"(http|rest|webclient|okhttp|url|socket|webservice)", re.I)),
    ("fs", re.compile(r"(file|path|filesystem|nio)", re.I)),
    ("exec", re.compile(r"(processbuilder|exec|eval)", re.I)),
    ("deserialize", re.compile(r"(deserialize|objectmapper|gson|kryo|fastjson)", re.I)),
]

def pick(patterns, text, default):
    for val, pat in patterns:
        if pat.search(text or ""):
            return val
    return default


def derive_for_finding(f):
    path = f.get("location", {}).get("file") or f.get("evidence", {}).get("file") or ""
    layer = f.get("layer") or pick(LAYER_PATTERNS, path, "unknown_layer")
    boundary = f.get("boundary") or pick(BOUNDARY_PATTERNS, path, "unknown_boundary")
    sink_class = f.get("sink_class") or pick(SINK_PATTERNS, path, "unknown_sink_class")
    f["layer"] = layer
    f["boundary"] = boundary
    f["sink_class"] = sink_class


def main(paths):
    changed = 0
    for p in paths:
        path = Path(p)
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        for f in findings:
            if isinstance(f, dict):
                derive_for_finding(f)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        changed += 1
        print(f"updated facets: {path}")
    print(f"done: {changed} files")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1:])
