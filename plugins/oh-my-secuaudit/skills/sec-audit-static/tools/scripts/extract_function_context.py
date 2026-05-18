#!/usr/bin/env python3
"""Extract function/method context for file:line hits with robust fallbacks.

Priority:
1) tree-sitter enclosing function/method node
2) tree-sitter retry with alternate language
3) brace-block heuristic
4) fixed +/- line window
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

try:
    from tree_sitter import Parser
    from tree_sitter_languages import get_language
except Exception:
    Parser = None
    get_language = None


FUNC_NODE_TYPES = {
    "method_declaration",
    "function_declaration",
    "constructor_declaration",
    "primary_constructor",
}


def parse_hits(path: Path, allow_exts: set[str]) -> list[tuple[Path, int]]:
    hits: list[tuple[Path, int]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^(.*?):(\d+):", line.strip())
        if not m:
            continue
        f = Path(m.group(1))
        if f.exists() and f.suffix.lower() in allow_exts:
            hits.append((f, int(m.group(2))))
    return hits


def parser_for(lang_name: str):
    if Parser is None or get_language is None:
        return None
    parser = Parser()
    lang = get_language(lang_name)
    if hasattr(parser, "set_language"):
        parser.set_language(lang)
    else:
        parser.language = lang
    return parser


def tree_sitter_extract(file_path: Path, line_no: int, lang_name: str):
    parser = parser_for(lang_name)
    if parser is None:
        return None
    src = file_path.read_bytes()
    tree = parser.parse(src)

    target_row = max(line_no - 1, 0)
    root = tree.root_node

    # Compatibility path: some tree_sitter versions in Python do not expose
    # descendant_for_point_range APIs. Fall back to a DFS enclosure search.
    def encloses(node):
        srow, scol = node.start_point
        erow, ecol = node.end_point
        if target_row < srow or target_row > erow:
            return False
        if target_row == srow and 0 < scol:
            return False
        if target_row == erow and 0 > ecol:
            return False
        return True

    def find_smallest(node):
        if not encloses(node):
            return None
        for ch in getattr(node, "children", []) or []:
            found = find_smallest(ch)
            if found is not None:
                return found
        return node

    target = find_smallest(root)
    if target is None:
        return None
    n = target
    while n:
        if n.type in FUNC_NODE_TYPES:
            start = n.start_point[0] + 1
            end = n.end_point[0] + 1
            return {
                "start_line": start,
                "end_line": end,
                "extract_method": f"tree_sitter:{lang_name}",
            }
        n = n.parent
    return None


def brace_fallback(lines: list[str], line_no: int):
    i = max(0, line_no - 1)

    # search backward for probable declaration line
    decl_pat = re.compile(
        r"(?:\b(public|private|protected|static|final|synchronized)\b.*)?"
        r"(?:\b(class|interface)\b|\b[A-Za-z_][\w<>\[\],\s]*\b\s+[A-Za-z_]\w*\s*\()"
    )
    start = i
    for j in range(i, max(-1, i - 250), -1):
        if decl_pat.search(lines[j]):
            start = j
            break

    # find opening brace near start..i
    open_idx = None
    for j in range(start, min(i + 1, len(lines))):
        if "{" in lines[j]:
            open_idx = j
            break
    if open_idx is None:
        return None

    depth = 0
    close_idx = None
    for j in range(open_idx, min(len(lines), open_idx + 1200)):
        depth += lines[j].count("{")
        depth -= lines[j].count("}")
        if depth <= 0 and j > open_idx:
            close_idx = j
            break
    if close_idx is None:
        return None

    return {
        "start_line": open_idx + 1,
        "end_line": close_idx + 1,
        "extract_method": "brace_fallback",
    }


def window_fallback(lines: list[str], line_no: int, radius: int):
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    return {
        "start_line": start,
        "end_line": end,
        "extract_method": f"window_fallback:+/-{radius}",
    }


def run_extract(file_path: Path, line_no: int, radius: int):
    ext = file_path.suffix.lower()
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()

    # 1) preferred language
    if ext == ".java":
        first = tree_sitter_extract(file_path, line_no, "java")
        second = tree_sitter_extract(file_path, line_no, "kotlin")
    elif ext == ".kt":
        first = tree_sitter_extract(file_path, line_no, "kotlin")
        second = tree_sitter_extract(file_path, line_no, "java")
    else:
        first = None
        second = None

    if first:
        result = first
    elif second:
        result = second
    else:
        result = brace_fallback(lines, line_no)
        if not result:
            result = window_fallback(lines, line_no, radius)

    s = result["start_line"] - 1
    e = result["end_line"]
    snippet = "\n".join(lines[s:e])
    result["file"] = str(file_path)
    result["line"] = line_no
    result["snippet"] = snippet
    result["snippet_chars"] = len(snippet)
    result["estimated_tokens"] = len(snippet) // 4
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hits", required=True, help="Path to file:line hit list")
    ap.add_argument("--out", required=True, help="Output JSON path")
    ap.add_argument("--radius", type=int, default=40, help="Window fallback radius")
    ap.add_argument("--max", type=int, default=30, help="Max hits to extract")
    ap.add_argument(
        "--exts",
        default=".java,.kt",
        help="Comma-separated extensions to include from hit list (default: .java,.kt)",
    )
    ap.add_argument(
        "--dedup-function",
        dest="dedup_function",
        action="store_true",
        default=True,
        help="Deduplicate contexts by (file,start_line,end_line) (default: on)",
    )
    ap.add_argument(
        "--no-dedup-function",
        dest="dedup_function",
        action="store_false",
        help="Disable function-range deduplication",
    )
    args = ap.parse_args()

    allow_exts = {e.strip().lower() for e in args.exts.split(",") if e.strip()}
    hits = parse_hits(Path(args.hits), allow_exts)[: args.max]
    out = []
    seen_func = set()
    for file_path, line_no in hits:
        try:
            item = run_extract(file_path, line_no, args.radius)
            if args.dedup_function:
                key = (
                    item.get("file", str(file_path)),
                    int(item.get("start_line", line_no)),
                    int(item.get("end_line", line_no)),
                )
                if key in seen_func:
                    continue
                seen_func.add(key)
            out.append(item)
        except Exception:
            continue

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
