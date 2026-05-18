#!/usr/bin/env python3
"""Extract Spring/Kotlin endpoints via lightweight regex (rg-style parsing).

Outputs Task 2-1 JSON with findings list.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ANNOTATION_METHODS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

REQ_METHOD_RE = re.compile(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)")
QUOTED_RE = re.compile(r"\"([^\"]+)\"")

REQ_PARAM_RE = re.compile(r"@RequestParam\(([^)]*)\)")
PATH_VAR_RE = re.compile(r"@PathVariable\(([^)]*)\)")


def normalize_path(base: str, sub: str) -> str:
    if not base:
        return sub or "/"
    if not sub:
        return base
    if base.endswith("/") and sub.startswith("/"):
        return base[:-1] + sub
    if not base.endswith("/") and not sub.startswith("/"):
        return base + "/" + sub
    return base + sub


def extract_paths(text: str) -> list[str]:
    # Collect all quoted strings in annotation args
    paths = QUOTED_RE.findall(text)
    return [p for p in paths if p.startswith("/")] or ([paths[0]] if paths else [])


def extract_params(lines: list[str], start: int, max_lines: int = 8) -> list[str]:
    params: list[str] = []
    for i in range(start, min(len(lines), start + max_lines)):
        line = lines[i]
        for m in REQ_PARAM_RE.findall(line):
            names = QUOTED_RE.findall(m)
            if names:
                params.extend(names)
        for m in PATH_VAR_RE.findall(line):
            names = QUOTED_RE.findall(m)
            if names:
                params.extend(names)
    return sorted(set(params))


def _read_annotation(lines: list[str], start: int) -> tuple[str, int]:
    """Read multi-line annotation text starting at `start` and return (text, next_index)."""
    buf = []
    i = start
    depth = 0
    started = False
    while i < len(lines):
        line = lines[i].strip()
        if not started:
            if not line.startswith("@"):
                return "", start
            started = True
        buf.append(line)
        depth += line.count("(") - line.count(")")
        if depth <= 0 and started:
            return " ".join(buf), i + 1
        i += 1
    return " ".join(buf), i


def _annotation_name(text: str) -> str:
    if not text.startswith("@"):
        return ""
    name = text[1:].split("(", 1)[0]
    return name.split(".")[-1].strip()


def _is_class_decl(line: str) -> bool:
    s = line.strip()
    return (
        s.startswith("class ")
        or s.startswith("interface ")
        or s.startswith("enum ")
        or s.startswith("object ")
        or " class " in s
    )


def _is_method_decl(line: str) -> bool:
    s = line.strip()
    return (
        s.startswith("fun ")
        or s.startswith("public ")
        or s.startswith("private ")
        or s.startswith("protected ")
        or " fun " in s
        or "(" in s and s.endswith("{")
    )


def scan_file(path: Path) -> list[dict]:
    findings: list[dict] = []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    class_base = ""
    pending_annotations: list[str] = []

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if stripped.startswith("@"):
            anno_text, next_idx = _read_annotation(lines, idx)
            if anno_text:
                pending_annotations.append(anno_text)
                idx = next_idx
                # lookahead for class/method declaration
                for j in range(idx, min(len(lines), idx + 4)):
                    if _is_class_decl(lines[j]):
                        # class-level annotations
                        base_paths: list[str] = []
                        for ann in pending_annotations:
                            if _annotation_name(ann) == "RequestMapping":
                                base_paths.extend(extract_paths(ann))
                        if base_paths:
                            class_base = base_paths[0]
                        pending_annotations = []
                        break
                    if _is_method_decl(lines[j]):
                        # method-level annotations
                        for ann in pending_annotations:
                            ann_name = _annotation_name(ann)
                            if ann_name in ANNOTATION_METHODS:
                                paths = extract_paths(ann) or [""]
                                params = extract_params(lines, j)
                                for p in paths:
                                    api = normalize_path(class_base, p)
                                    findings.append({
                                        "api": api,
                                        "method": ANNOTATION_METHODS[ann_name],
                                        "file": f"{path}:{idx}",
                                        "auth_required": "unknown",
                                        "parameters": params,
                                    })
                            elif ann_name == "RequestMapping":
                                paths = extract_paths(ann) or [""]
                                methods = REQ_METHOD_RE.findall(ann) or ["UNKNOWN"]
                                params = extract_params(lines, j)
                                for m in methods:
                                    for p in paths:
                                        api = normalize_path(class_base, p)
                                        findings.append({
                                            "api": api,
                                            "method": m,
                                            "file": f"{path}:{idx}",
                                            "auth_required": "unknown",
                                            "parameters": params,
                                        })
                        pending_annotations = []
                        break
                continue

        idx += 1

    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Source repo root")
    ap.add_argument("--out", required=True, help="Output JSON path")
    ap.add_argument(
        "--source-repo-url",
        required=True,
        help="진단 대상 레포 URL",
    )
    ap.add_argument(
        "--source-repo-path",
        required=True,
        help="로컬 레포 경로",
    )
    ap.add_argument(
        "--source-modules",
        required=True,
        help="진단 대상 모듈/서브프로젝트 (comma-separated)",
    )
    args = ap.parse_args()

    root = Path(args.repo)
    files = list(root.rglob("*.kt")) + list(root.rglob("*.java"))

    findings: list[dict] = []
    for f in files:
        # skip build/decompiled output
        if "/target/" in f.as_posix() or "/build/" in f.as_posix() or "/decompiled/" in f.as_posix():
            continue
        findings.extend(scan_file(f))

    modules = [m.strip() for m in args.source_modules.split(",") if m.strip()]
    if not modules:
        raise SystemExit("Error: --source-modules 값이 비어 있습니다.")

    out = {
        "task_id": "2-1",
        "status": "completed",
        "findings": findings,
        "executed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "metadata": {
            "source_repo_url": args.source_repo_url,
            "source_repo_path": args.source_repo_path,
            "source_modules": modules,
            "tool": "extract_endpoints_rg",
            "files_scanned": len(files),
            "notes": "regex-based extraction; auth_required defaults to unknown",
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
