#!/usr/bin/env python3
"""
Ensure required metadata fields exist in task result JSONs.

Usage:
  python tools/scripts/ensure_metadata.py \
    --state-dir state \
    --glob "task_*_result.json" \
    --source-repo-url "http://example/repo.git" \
    --source-repo-path "/path/to/repo" \
    --source-modules "module-a,module-b"
"""

import argparse
import json
import sys
from pathlib import Path


REQUIRED_FIELDS = [
    "source_repo_url",
    "source_repo_path",
    "source_modules",
]


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def parse_modules(value: str | None) -> list[str] | None:
    if value is None:
        return None
    modules = [m.strip() for m in value.split(",") if m.strip()]
    return modules if modules else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Ensure required metadata fields exist in task JSONs.")
    parser.add_argument("--state-dir", "-d", default="state/", help="state 폴더 경로")
    parser.add_argument("--glob", "-g", default="task_*_result.json", help="파일 매칭 glob 패턴")
    parser.add_argument("--source-repo-url", help="metadata.source_repo_url 값")
    parser.add_argument("--source-repo-path", help="metadata.source_repo_path 값")
    parser.add_argument("--source-modules", help="metadata.source_modules 값 (comma-separated)")
    parser.add_argument("--source-label", help="metadata.source_label 값 (optional)")
    parser.add_argument("--report-wiki-url", help="metadata.report_wiki_url 값 (optional)")
    parser.add_argument("--report-wiki-page-id", help="metadata.report_wiki_page_id 값 (optional)")
    parser.add_argument("--report-wiki-status", help="metadata.report_wiki_status 값 (optional)")
    parser.add_argument("--dry-run", action="store_true", help="파일 변경 없이 누락 항목만 출력")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    if not state_dir.exists():
        print(f"Error: state 폴더를 찾을 수 없습니다: {state_dir}")
        return 1

    modules = parse_modules(args.source_modules)
    defaults = {
        "source_repo_url": args.source_repo_url,
        "source_repo_path": args.source_repo_path,
        "source_modules": modules,
        "source_label": args.source_label,
        "report_wiki_url": args.report_wiki_url,
        "report_wiki_page_id": args.report_wiki_page_id,
        "report_wiki_status": args.report_wiki_status,
    }

    missing_overall: dict[str, list[str]] = {}
    updated = 0
    total = 0

    for json_file in sorted(state_dir.glob(args.glob)):
        total += 1
        try:
            data = load_json(json_file)
        except (json.JSONDecodeError, IOError) as exc:
            print(f"Warning: {json_file} 로드 실패: {exc}")
            continue

        meta = data.get("metadata")
        if meta is None:
            meta = {}
            data["metadata"] = meta

        missing = []
        changed = False
        for field in REQUIRED_FIELDS:
            if meta.get(field):
                continue
            if defaults.get(field) is not None:
                meta[field] = defaults[field]
                changed = True
            else:
                missing.append(field)

        if args.source_label and not meta.get("source_label"):
            meta["source_label"] = args.source_label
            changed = True

        if args.report_wiki_url and not meta.get("report_wiki_url"):
            meta["report_wiki_url"] = args.report_wiki_url
            changed = True
        if args.report_wiki_page_id and not meta.get("report_wiki_page_id"):
            meta["report_wiki_page_id"] = args.report_wiki_page_id
            changed = True
        if args.report_wiki_status and not meta.get("report_wiki_status"):
            meta["report_wiki_status"] = args.report_wiki_status
            changed = True

        if missing:
            missing_overall[json_file.name] = missing

        if changed:
            updated += 1
            if not args.dry_run:
                write_json(json_file, data)

    print(f"검사 파일: {total}건, 업데이트: {updated}건")
    if missing_overall:
        print("누락된 필수 metadata:")
        for name, fields in missing_overall.items():
            print(f"  - {name}: {', '.join(fields)}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
