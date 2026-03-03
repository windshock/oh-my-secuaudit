#!/usr/bin/env python3
"""Extract Spring/Kotlin endpoints using tree-sitter (higher precision).

Requires: tree_sitter, tree_sitter_languages
  pip install tree_sitter tree_sitter_languages

Outputs Task 2-1 JSON with findings list.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "tree-sitter not available. Install with: pip install tree_sitter tree_sitter_languages"
    ) from exc

ANNOTATION_METHODS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}


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


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _extract_string_literals(src: bytes, node) -> list[str]:
    out: list[str] = []
    if node.type == "string_literal":
        text = _node_text(src, node)
        if text.startswith('"') and text.endswith('"'):
            out.append(text[1:-1])
        return out
    for c in node.children:
        out.extend(_extract_string_literals(src, c))
    return out


def _annotation_name(text: str) -> str:
    # Extract simple annotation name from text like @RequestMapping(...)
    m = None
    if text.startswith("@"):
        m = text[1:].split("(", 1)[0]
    name = (m or "").split(".")[-1]
    return name.strip()


def _extract_request_methods(text: str) -> list[str]:
    methods = []
    for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
        if f"RequestMethod.{m}" in text:
            methods.append(m)
    return methods


def _extract_paths_from_annotation(src: bytes, node) -> list[str]:
    # allow relative paths; normalize later with base
    return [p for p in _extract_string_literals(src, node)]


def _find_annotations(root):
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in {"annotation", "marker_annotation", "single_element_annotation"}:
            yield node
        # add children for full traversal
        for child in node.children:
            stack.append(child)


def _collect_annotations(node):
    """Collect annotations from modifiers or direct children."""
    ann_nodes = []
    # modifiers field (java/kotlin)
    modifiers = None
    if hasattr(node, "child_by_field_name"):
        modifiers = node.child_by_field_name("modifiers")
    # java tree-sitter may not expose modifiers as a field
    if not modifiers:
        for child in node.children:
            if child.type == "modifiers":
                modifiers = child
                break
    if modifiers:
        ann_nodes.extend(list(_find_annotations(modifiers)))
    # direct annotations
    for child in node.children:
        if child.type in {"annotation", "marker_annotation", "single_element_annotation"}:
            ann_nodes.append(child)
    return ann_nodes


def scan_file(path: Path) -> list[dict]:
    src = path.read_bytes()
    parser = Parser()
    lang = get_language("java") if path.suffix == ".java" else get_language("kotlin")
    # tree_sitter API differs by version
    if hasattr(parser, "set_language"):
        parser.set_language(lang)
    else:
        parser.language = lang
    tree = parser.parse(src)

    findings: list[dict] = []

    # Build class-level base mappings
    class_base_map: dict[tuple[int, int], list[str]] = {}
    for node in tree.root_node.children:
        if node.type not in {"class_declaration", "object_declaration", "interface_declaration"}:
            continue
        bases: list[str] = []
        # Collect annotations under modifiers or direct children
        for ann in _collect_annotations(node):
            text = _node_text(src, ann)
            if _annotation_name(text) == "RequestMapping":
                paths = _extract_paths_from_annotation(src, ann)
                bases.extend(paths)
        class_base_map[(node.start_byte, node.end_byte)] = bases or [""]

    # Method/function-level mappings (manual traversal)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in {"method_declaration", "function_declaration"}:
            # Find enclosing class for base path
            base_paths = [""]
            p = node.parent
            while p:
                if p.type in {"class_declaration", "object_declaration", "interface_declaration"}:
                    base_paths = class_base_map.get((p.start_byte, p.end_byte), [""])
                    break
                p = p.parent

            # Extract annotations on method/function
            ann_nodes = _collect_annotations(node)

            for ann in ann_nodes:
                text = _node_text(src, ann)
                name = _annotation_name(text)
                if name in ANNOTATION_METHODS:
                    paths = _extract_paths_from_annotation(src, ann) or [""]
                    for base in base_paths:
                        for pth in paths:
                            findings.append({
                                "api": normalize_path(base, pth),
                                "method": ANNOTATION_METHODS[name],
                                "file": f"{path}:{ann.start_point[0] + 1}",
                                "auth_required": "unknown",
                                "parameters": [],
                            })
                elif name == "RequestMapping":
                    paths = _extract_paths_from_annotation(src, ann) or [""]
                    methods = _extract_request_methods(text) or ["UNKNOWN"]
                    for base in base_paths:
                        for pth in paths:
                            for m in methods:
                                findings.append({
                                    "api": normalize_path(base, pth),
                                    "method": m,
                                    "file": f"{path}:{ann.start_point[0] + 1}",
                                    "auth_required": "unknown",
                                    "parameters": [],
                                })
        # traverse children
        for child in node.children:
            stack.append(child)

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
        if "/target/" in f.as_posix() or "/build/" in f.as_posix() or "/decompiled/" in f.as_posix():
            continue
        try:
            findings.extend(scan_file(f))
        except Exception:
            continue

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
            "tool": "extract_endpoints_treesitter",
            "files_scanned": len(files),
            "notes": "tree-sitter extraction; auth_required defaults to unknown",
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
