#!/usr/bin/env python3
"""
High-risk auth key exposure scan.

Purpose:
- Detect exposed key/iv response endpoints (e.g. DBIF 0002/getAuthkeyInfo)
- Detect hardcoded crypto key/iv material in source/test/build artifacts

Output:
- task JSON compatible with sec-audit-static task schema
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


HEX_KEY_RE = re.compile(r'(?i)\b(?:key|iv)\b\s*=\s*"([0-9a-f]{32})"')
PROP_KEY_RE = re.compile(r"^APP\.CIPHER\.AES\.KEY\.[A-Z0-9_.-]+\s*=\s*([^\n#]+)$", re.MULTILINE)
ENDPOINT_RE = re.compile(r"/appserver/0002\.json|getAuthkeyInfo\.json")
PUT_KEY_RE = re.compile(r'res\.put\(\s*"key"\s*,')
PUT_IV_RE = re.compile(r'res\.put\(\s*"iv"\s*,')


def run_rg(pattern: str, root: Path) -> list[tuple[Path, int, str]]:
    cmd = ["rg", "-n", "-S", "--no-messages", pattern, str(root)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = []
    for line in proc.stdout.splitlines():
        # format: /path/file:line:text
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path_s, line_s, text = parts
        try:
            lineno = int(line_s)
        except ValueError:
            continue
        out.append((Path(path_s), lineno, text.strip()))
    return out


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def unique_paths(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        rp = str(p.resolve())
        if rp in seen:
            continue
        seen.add(rp)
        out.append(p.resolve())
    return out


def discover_roots(primary: Path, extras: list[Path]) -> list[Path]:
    roots = unique_paths([primary, *extras])

    # Cross-module default guard: appif* repo often has sibling dbif for auth key chain.
    pname = primary.name.lower()
    sibling_dbif = primary.parent / "dbif"
    if pname.startswith("appif") and sibling_dbif.exists() and sibling_dbif.is_dir():
        roots = unique_paths([*roots, sibling_dbif])

    return [p for p in roots if p.exists() and p.is_dir()]


def common_repo_root(roots: list[Path]) -> Path:
    if not roots:
        return Path(".").resolve()
    parents = [r.resolve() for r in roots]
    while len({str(p) for p in parents}) > 1:
        parents = [p.parent for p in parents]
    return parents[0]


def rel(repo_root: Path, p: Path) -> str:
    try:
        return str(p.resolve().relative_to(repo_root.resolve()))
    except Exception:
        return str(p.resolve())


def find_endpoint_exposure(repo_root: Path, roots: list[Path]) -> dict | None:
    hits: list[tuple[Path, int, str]] = []
    for root in roots:
        hits.extend(run_rg(r"/appserver/0002\.json|getAuthkeyInfo\.json", root))

    for path, lineno, text in hits:
        if not path.suffix.lower() in {".java", ".kt"}:
            continue
        body = read_text(path)
        if ENDPOINT_RE.search(body) and PUT_KEY_RE.search(body) and PUT_IV_RE.search(body):
            return {
                "id": "KEY-001",
                "title": "Auth key material exposed by key-info endpoint",
                "severity": "High",
                "category": "data_protection",
                "description": "Endpoint exposes cryptographic key/iv values (AUTHKEY material) in response payload.",
                "location": {"file": rel(repo_root, path), "line": lineno},
                "evidence": {
                    "file": rel(repo_root, path),
                    "lines": [lineno],
                    "snippet": text,
                },
                "impact": "Anyone with network reachability to the endpoint can obtain key material and forge authKey tokens.",
                "recommendation": "Block endpoint from client/network exposure, require service authentication (mTLS + ACL), and stop returning key/iv over HTTP.",
                "flow": [
                    "Request reaches getAuthkeyInfo/0002 endpoint",
                    "Server reads AUTHKEY from code table (subCd_01/subCd_02)",
                    "Response returns key and iv fields to caller",
                ],
                "request_mapping": "/dbif5/appserver/0002.json",
                "layer": "controller",
                "boundary": "network",
                "sink_class": "net",
                "rank_score": 5.0,
                "slice_budget_used": 0,
                "edge_source": "snapshot",
                "confidence": 0.95,
            }
    return None


def find_hardcoded_crypto(repo_root: Path, roots: list[Path]) -> dict | None:
    evidences: list[tuple[Path, int, str]] = []
    for root in roots:
        # source/test/build artifacts
        targets = [root / "src", root / "target"]
        for t in targets:
            if t.exists():
                evidences.extend(run_rg(r'(?i)\b(key|iv)\b\s*=\s*"[0-9a-f]{32}"', t))

        # property-based static keys (non-placeholder)
        for prop in root.rglob("vmConfig.properties"):
            txt = read_text(prop)
            for m in PROP_KEY_RE.finditer(txt):
                val = m.group(1).strip()
                if "${" in val:
                    continue
                line_no = txt[: m.start()].count("\n") + 1
                evidences.append((prop, line_no, f"APP.CIPHER.AES.KEY...={val}"))

    if not evidences:
        return None

    first = evidences[0]
    lines = sorted({ln for _, ln, _ in evidences[:10]})
    return {
        "id": "KEY-002",
        "title": "Hardcoded cryptographic keys in code/config/artifacts",
        "severity": "High",
        "category": "data_protection",
        "description": "Hardcoded key/iv material is present across source/tests/build artifacts, enabling token forgery if leaked.",
        "location": {"file": rel(repo_root, first[0]), "line": first[1]},
        "evidence": {
            "file": rel(repo_root, first[0]),
            "lines": lines,
            "snippet": "[redacted hardcoded key material]",
        },
        "impact": "Exposed constants allow offline authKey generation/decryption and weaken trust boundaries.",
        "recommendation": "Remove hardcoded key material, migrate to KMS/Secret Manager runtime injection, rotate existing keys, and purge leaked build artifacts.",
        "flow": [
            "Attacker obtains repository/build artifact access",
            "Hardcoded key/iv constants are extracted",
            "Extracted material is used to generate or decrypt authKey payloads",
        ],
        "request_mapping": "internal/config+artifact",
        "layer": "config",
        "boundary": "file",
        "sink_class": "unknown_sink_class",
        "rank_score": 5.0,
        "slice_budget_used": 0,
        "edge_source": "snapshot",
        "confidence": 0.93,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan auth key exposure risks")
    parser.add_argument("--repo", required=True, help="Primary repo/module path")
    parser.add_argument("--extra-repo", action="append", default=[], help="Additional repo/module paths")
    parser.add_argument("--output", required=True, help="Task output JSON path")
    parser.add_argument("--state-store-run-id", default="", help="state_store_run_id metadata")
    parser.add_argument(
        "--snapshot-scope",
        default="module",
        choices=["module", "repo", "decompiled-module", "decompiled-repo"],
        help="snapshot scope metadata",
    )
    args = parser.parse_args()

    primary = Path(args.repo).resolve()
    extras = [Path(p).resolve() for p in args.extra_repo]
    roots = discover_roots(primary, extras)
    repo_root = common_repo_root(roots)

    findings = []
    f1 = find_endpoint_exposure(repo_root, roots)
    if f1:
        findings.append(f1)
    f2 = find_hardcoded_crypto(repo_root, roots)
    if f2:
        findings.append(f2)

    result = {
        "task_id": "2-6",
        "status": "completed",
        "findings": findings,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "notes": f"scan_authkey_exposure roots={','.join(str(r) for r in roots)}",
        "metadata": {
            "source_repo_url": f"file://{repo_root}",
            "source_repo_path": str(repo_root),
            "source_modules": [r.name for r in roots],
            "state_store_run_id": args.state_store_run_id or "RUN-UNKNOWN",
            "snapshot_scope": args.snapshot_scope,
        },
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {out} findings={len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
