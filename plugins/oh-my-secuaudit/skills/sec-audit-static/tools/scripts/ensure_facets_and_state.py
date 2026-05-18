#!/usr/bin/env python3
"""
Ensure facet tags and state metadata exist in task/finding JSONs.

- Fills metadata.state_store_run_id and metadata.snapshot_scope when missing.
- Adds facet defaults (layer/boundary/sink_class) to each finding when missing.
Usage:
  python tools/scripts/ensure_facets_and_state.py state/task_25_result.json --state-store-run-id RUN123 --snapshot-scope module
  python tools/scripts/ensure_facets_and_state.py state/*.json --state-store-run-id RUN123 --snapshot-scope decompiled-module --layer util
"""

import argparse
import json
import sys
from pathlib import Path

ALLOWED_LAYERS = {"controller", "service", "dao", "util", "unknown_layer"}
ALLOWED_BOUNDARIES = {"external", "network", "file", "deserialization", "unknown_boundary"}
ALLOWED_SINK_CLASSES = {"exec", "eval", "sql", "fs", "net", "deserialize", "unknown_sink_class"}
ALLOWED_SNAPSHOT_SCOPES = {"module", "repo", "decompiled-module", "decompiled-repo"}


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> int:
    p = argparse.ArgumentParser(description="Fill facet tags and state metadata in task JSONs.")
    p.add_argument("files", nargs="+", help="JSON 파일 경로 (glob 확장 쉘에서 처리)")
    p.add_argument("--state-store-run-id", required=True, help="metadata.state_store_run_id 값")
    p.add_argument("--snapshot-scope", default="module", choices=sorted(ALLOWED_SNAPSHOT_SCOPES), help="metadata.snapshot_scope 기본값")
    p.add_argument("--layer", default="unknown_layer", choices=sorted(ALLOWED_LAYERS), help="기본 layer 값")
    p.add_argument("--boundary", default="unknown_boundary", choices=sorted(ALLOWED_BOUNDARIES), help="기본 boundary 값")
    p.add_argument("--sink-class", default="unknown_sink_class", choices=sorted(ALLOWED_SINK_CLASSES), help="기본 sink_class 값")
    p.add_argument("--dry-run", action="store_true", help="파일을 수정하지 않고 변화만 보고")
    args = p.parse_args()

    default_layer = args.layer
    default_boundary = args.boundary
    default_sink = args.sink_class

    changed_files = 0
    for file_str in args.files:
        path = Path(file_str)
        if not path.exists():
            print(f"skip (not found): {path}")
            continue
        try:
            data = load_json(path)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"skip (load error): {path} ({exc})")
            continue

        meta = data.setdefault("metadata", {})
        meta_changed = False
        if not meta.get("state_store_run_id"):
            meta["state_store_run_id"] = args.state_store_run_id
            meta_changed = True
        if not meta.get("snapshot_scope"):
            meta["snapshot_scope"] = args.snapshot_scope
            meta_changed = True

        findings = data.get("findings", [])
        findings_changed = False
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                if f.get("layer") not in ALLOWED_LAYERS:
                    f["layer"] = default_layer
                    findings_changed = True
                if f.get("boundary") not in ALLOWED_BOUNDARIES:
                    f["boundary"] = default_boundary
                    findings_changed = True
                if f.get("sink_class") not in ALLOWED_SINK_CLASSES:
                    f["sink_class"] = default_sink
                    findings_changed = True

        if meta_changed or findings_changed:
            changed_files += 1
            if args.dry_run:
                print(f"would update: {path}")
            else:
                write_json(path, data)
                print(f"updated: {path}")

    print(f"done. changed files: {changed_files}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
