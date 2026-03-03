#!/usr/bin/env python3
"""
Manage the State Store SQLite database for sec-audit-static.

Supports:
  - init                     : create tables/indexes
  - add-run                  : insert a run record
  - add-candidate            : insert a candidate (optionally hash anchor)
  - update-candidate         : update status/score/facets/version
  - add-artifact             : insert artifact metadata
  - add-coverage             : insert normalized coverage summary
  - add-log                  : append provenance log entry

Schema is aligned with references/state_store_spec.md.
"""

import argparse
import hashlib
import sqlite3
import sys
import time
import uuid
from typing import Optional


STATUS_ENUM = {
    "reachable",
    "suspect",
    "unknown_no_edges",
    "unknown_dynamic_dispatch",
    "unknown_context_budget",
    "unknown_needs_runtime",
    "unknown_tooling_error",
    "indeterminate_policy",
    "benign_unreachable",
}

DEFAULT_DB = "state_store.db"


def utc_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS run (
            run_id TEXT PRIMARY KEY,
            tool TEXT,
            command TEXT,
            snapshot_scope TEXT,
            snapshot_name TEXT,
            started_at TEXT,
            ended_at TEXT,
            exit_code INTEGER,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS candidate (
            candidate_id TEXT PRIMARY KEY,
            family_id TEXT,
            repo TEXT,
            module TEXT,
            path TEXT,
            function TEXT,
            line_range TEXT,
            addr TEXT,
            bbid TEXT,
            sink_symbol_or_api TEXT,
            is_decompiled INTEGER DEFAULT 0,
            layer TEXT,
            boundary TEXT,
            sink_class TEXT,
            status TEXT,
            risk_score REAL,
            rank_hint REAL,
            path_depth_hint REAL,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT,
            version INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS artifact (
            artifact_id TEXT PRIMARY KEY,
            candidate_id TEXT,
            run_id TEXT,
            layer TEXT,
            type TEXT,
            path TEXT,
            content_hash TEXT,
            edge_source TEXT,
            confidence REAL,
            note TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(candidate_id) REFERENCES candidate(candidate_id) ON DELETE CASCADE,
            FOREIGN KEY(run_id) REFERENCES run(run_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS coverage_summary (
            coverage_id TEXT PRIMARY KEY,
            candidate_id TEXT,
            run_id TEXT,
            tool TEXT,
            covered_functions_count INTEGER,
            covered_basic_blocks_count INTEGER,
            time_seconds REAL,
            seed_count INTEGER,
            crash INTEGER,
            crash_trace TEXT,
            repro_path TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(candidate_id) REFERENCES candidate(candidate_id) ON DELETE CASCADE,
            FOREIGN KEY(run_id) REFERENCES run(run_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS provenance_log (
            entry_id TEXT PRIMARY KEY,
            run_id TEXT,
            severity TEXT,
            message TEXT,
            prev_hash TEXT,
            entry_hash TEXT,
            ts TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(run_id) REFERENCES run(run_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_candidate_status ON candidate(status);
        CREATE INDEX IF NOT EXISTS idx_candidate_family ON candidate(family_id);
        CREATE INDEX IF NOT EXISTS idx_candidate_sink_class ON candidate(sink_class);
        CREATE INDEX IF NOT EXISTS idx_candidate_module ON candidate(module);
        CREATE INDEX IF NOT EXISTS idx_artifact_candidate ON artifact(candidate_id);
        CREATE INDEX IF NOT EXISTS idx_artifact_run ON artifact(run_id);
        CREATE INDEX IF NOT EXISTS idx_cov_candidate ON coverage_summary(candidate_id);
        CREATE INDEX IF NOT EXISTS idx_cov_run ON coverage_summary(run_id);
        CREATE INDEX IF NOT EXISTS idx_log_run ON provenance_log(run_id);
        """
    )
    # schema upgrades
    cur.execute("PRAGMA table_info(artifact)")
    cols = {row[1] for row in cur.fetchall()}
    if "edge_source" not in cols:
        cur.execute("ALTER TABLE artifact ADD COLUMN edge_source TEXT")
    cur.execute("PRAGMA table_info(provenance_log)")
    cols = {row[1] for row in cur.fetchall()}
    if "prev_hash" not in cols:
        cur.execute("ALTER TABLE provenance_log ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in cols:
        cur.execute("ALTER TABLE provenance_log ADD COLUMN entry_hash TEXT")
    conn.commit()


def hash_anchor(repo: str, path: str, function: str, line_range: str, sink_symbol: str, addr: str, bbid: str) -> str:
    parts = [repo or "", path or "", function or "", line_range or "", sink_symbol or "", addr or "", bbid or ""]
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def add_run(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    run_id = args.run_id or str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO run (run_id, tool, command, snapshot_scope, snapshot_name, started_at, ended_at, exit_code, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            args.tool,
            args.command,
            args.snapshot_scope,
            args.snapshot_name,
            args.started_at or utc_ts(),
            args.ended_at,
            args.exit_code,
            utc_ts(),
        ),
    )
    conn.commit()
    print(run_id)


def add_candidate(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    candidate_id = args.candidate_id
    family_id = args.family_id
    if args.hash_anchor:
        candidate_id = candidate_id or hash_anchor(args.repo, args.path, args.function, args.line_range, args.sink_symbol_or_api, args.addr, args.bbid)
        if not family_id:
            family_id = hash_anchor(args.repo, args.path, args.function, "", args.sink_symbol_or_api, "", "")
    if not candidate_id:
        raise SystemExit("candidate_id is required (or use --hash-anchor with anchor fields)")
    if args.status and args.status not in STATUS_ENUM:
        raise SystemExit(f"invalid status '{args.status}'")
    conn.execute(
        """
        INSERT INTO candidate (
            candidate_id, family_id, repo, module, path, function, line_range, addr, bbid,
            sink_symbol_or_api, is_decompiled, layer, boundary, sink_class, status,
            risk_score, rank_hint, path_depth_hint, created_at, updated_at, version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            candidate_id,
            family_id,
            args.repo,
            args.module,
            args.path,
            args.function,
            args.line_range,
            args.addr,
            args.bbid,
            args.sink_symbol_or_api,
            1 if args.is_decompiled else 0,
            args.layer,
            args.boundary,
            args.sink_class,
            args.status or "unknown_no_edges",
            args.risk_score,
            args.rank_hint,
            args.path_depth_hint,
            utc_ts(),
            utc_ts(),
            1,
        ),
    )
    conn.commit()
    print(candidate_id)


def update_candidate(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    updates = []
    params = []
    if args.status:
        if args.status not in STATUS_ENUM:
            raise SystemExit(f"invalid status '{args.status}'")
        updates.append("status = ?")
        params.append(args.status)
    for field in ("risk_score", "rank_hint", "path_depth_hint", "layer", "boundary", "sink_class", "module"):
        val = getattr(args, field)
        if val is not None:
            updates.append(f"{field} = ?")
            params.append(val)
    if not updates:
        raise SystemExit("no fields to update")
    updates.append("updated_at = ?")
    params.append(utc_ts())
    updates.append("version = version + 1")
    sql = f"UPDATE candidate SET {', '.join(updates)} WHERE candidate_id = ?"
    params.append(args.candidate_id)
    cur = conn.execute(sql, params)
    if cur.rowcount == 0:
        raise SystemExit("candidate not found")
    conn.commit()


def add_artifact(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    artifact_id = args.artifact_id or str(uuid.uuid4())
    content_hash = args.content_hash
    if not content_hash and args.path:
        try:
            import hashlib, pathlib
            data = pathlib.Path(args.path).read_bytes()
            content_hash = hashlib.sha256(data).hexdigest()
        except OSError:
            content_hash = None
    conn.execute(
        """
        INSERT INTO artifact (artifact_id, candidate_id, run_id, layer, type, path, content_hash, edge_source, confidence, note, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            artifact_id,
            args.candidate_id,
            args.run_id,
            args.layer,
            args.type,
            args.path,
            content_hash,
            args.edge_source,
            args.confidence,
            args.note,
            utc_ts(),
        ),
    )
    conn.commit()
    print(artifact_id)


def add_coverage(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    coverage_id = args.coverage_id or str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO coverage_summary (
            coverage_id, candidate_id, run_id, tool, covered_functions_count,
            covered_basic_blocks_count, time_seconds, seed_count, crash, crash_trace, repro_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            coverage_id,
            args.candidate_id,
            args.run_id,
            args.tool,
            args.covered_functions_count,
            args.covered_basic_blocks_count,
            args.time_seconds,
            args.seed_count,
            1 if args.crash else 0,
            args.crash_trace,
            args.repro_path,
            utc_ts(),
        ),
    )
    conn.commit()
    print(coverage_id)


def add_log(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    entry_id = args.entry_id or str(uuid.uuid4())
    cur = conn.execute(
        "SELECT entry_hash FROM provenance_log WHERE run_id = ? ORDER BY ts DESC LIMIT 1",
        (args.run_id,),
    )
    row = cur.fetchone()
    prev_hash = row[0] if row else ""
    payload = f"{args.run_id}|{args.severity}|{args.message}|{utc_ts()}|{prev_hash}".encode("utf-8")
    entry_hash = hashlib.sha256(payload).hexdigest()
    conn.execute(
        """
        INSERT INTO provenance_log (entry_id, run_id, severity, message, prev_hash, entry_hash, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (entry_id, args.run_id, args.severity, args.message, prev_hash, entry_hash, utc_ts()),
    )
    conn.commit()
    print(entry_id)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Manage sec-audit-static state store (SQLite).")
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path (default: state_store.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create tables/indexes")

    prun = sub.add_parser("add-run", help="insert a run record")
    prun.add_argument("--run-id")
    prun.add_argument("--tool")
    prun.add_argument("--command")
    prun.add_argument("--snapshot-scope")
    prun.add_argument("--snapshot-name")
    prun.add_argument("--started-at")
    prun.add_argument("--ended-at")
    prun.add_argument("--exit-code", type=int)

    pcand = sub.add_parser("add-candidate", help="insert a candidate")
    pcand.add_argument("--candidate-id")
    pcand.add_argument("--family-id")
    pcand.add_argument("--repo")
    pcand.add_argument("--module")
    pcand.add_argument("--path")
    pcand.add_argument("--function")
    pcand.add_argument("--line-range")
    pcand.add_argument("--addr")
    pcand.add_argument("--bbid")
    pcand.add_argument("--sink-symbol-or-api")
    pcand.add_argument("--is-decompiled", action="store_true")
    pcand.add_argument("--layer")
    pcand.add_argument("--boundary")
    pcand.add_argument("--sink-class")
    pcand.add_argument("--status")
    pcand.add_argument("--risk-score", type=float)
    pcand.add_argument("--rank-hint", type=float)
    pcand.add_argument("--path-depth-hint", type=float)
    pcand.add_argument("--hash-anchor", action="store_true", help="hash anchor fields to derive candidate_id/family_id")

    pupdate = sub.add_parser("update-candidate", help="update candidate fields")
    pupdate.add_argument("candidate_id")
    pupdate.add_argument("--status")
    pupdate.add_argument("--risk-score", type=float)
    pupdate.add_argument("--rank-hint", type=float)
    pupdate.add_argument("--path-depth-hint", type=float)
    pupdate.add_argument("--layer")
    pupdate.add_argument("--boundary")
    pupdate.add_argument("--sink-class")
    pupdate.add_argument("--module")

    part = sub.add_parser("add-artifact", help="insert artifact metadata")
    part.add_argument("--artifact-id")
    part.add_argument("--candidate-id", required=True)
    part.add_argument("--run-id", required=True)
    part.add_argument("--layer", required=True)
    part.add_argument("--type", default="json")
    part.add_argument("--path")
    part.add_argument("--content-hash")
    part.add_argument("--edge-source", help="edge source tier: snapshot|lsp|grep")
    part.add_argument("--confidence", type=float)
    part.add_argument("--note")

    pcov = sub.add_parser("add-coverage", help="insert coverage summary")
    pcov.add_argument("--coverage-id")
    pcov.add_argument("--candidate-id", required=True)
    pcov.add_argument("--run-id", required=True)
    pcov.add_argument("--tool")
    pcov.add_argument("--covered-functions-count", type=int)
    pcov.add_argument("--covered-basic-blocks-count", type=int)
    pcov.add_argument("--time-seconds", type=float)
    pcov.add_argument("--seed-count", type=int)
    pcov.add_argument("--crash", action="store_true")
    pcov.add_argument("--crash-trace")
    pcov.add_argument("--repro-path")

    plog = sub.add_parser("add-log", help="append provenance log entry")
    plog.add_argument("--entry-id")
    plog.add_argument("--run-id", required=True)
    plog.add_argument("--severity", default="info")
    plog.add_argument("--message", required=True)

    return p.parse_args()


def main() -> None:
    args = parse_args()
    conn = connect(args.db)
    if args.cmd == "init":
        init_db(conn)
        print(f"initialized {args.db}")
    elif args.cmd == "add-run":
        add_run(conn, args)
    elif args.cmd == "add-candidate":
        add_candidate(conn, args)
    elif args.cmd == "update-candidate":
        update_candidate(conn, args)
    elif args.cmd == "add-artifact":
        add_artifact(conn, args)
    elif args.cmd == "add-coverage":
        add_coverage(conn, args)
    elif args.cmd == "add-log":
        add_log(conn, args)
    else:
        raise SystemExit(f"unknown cmd {args.cmd}")


if __name__ == "__main__":
    main()
