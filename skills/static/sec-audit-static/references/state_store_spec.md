# State Store Spec (Draft)

Purpose: centralized, queryable storage for all candidate artifacts across layers. Optimized for reproducibility, diffing, and auditability.

## Core entities
- `run`: one execution of the pipeline (fields: `run_id`, `tool`, `command`, `snapshot_scope`, `snapshot_name`, `started_at`, `ended_at`, `exit_code`).
- `candidate`: anchored by sink callsite and associated source cluster.
  - `candidate_id` (stable): `sha256(repo|path|function|line_range|sink_symbol_or_api)`; decompiled fallback uses `address|basic_block_id` in place of `line_range`.
  - `family_id`: hash of the sink anchor only.
  - Anchor fields: `repo`, `module`, `path`, `function`, `line_range` (or `addr`/`bbid`), `sink_symbol_or_api`, `is_decompiled`.
  - Facet fields: `layer` (controller/service/dao/util|unknown_layer), `boundary` (external/network/file/deserialization|unknown_boundary), `sink_class` (exec/eval/sql/fs/net/deserialize|unknown_sink_class).
  - Status enum: `reachable`, `suspect`, `unknown_no_edges`, `unknown_dynamic_dispatch`, `unknown_context_budget`, `unknown_needs_runtime`, `unknown_tooling_error`, `indeterminate_policy`, `benign_unreachable`.
  - Scores/hints: `risk_score`, `rank_hint`, `path_depth_hint`.
  - Timestamps: `created_at`, `updated_at`, `version`.

- `artifact`: arbitrary layer outputs bound to a candidate.
  - Fields: `artifact_id`, `candidate_id`, `run_id`, `layer` (retrieval|facet|edge|rank|static|dynamic|fuzz|slicing|report), `type` (json|text|blob), `path` (if filesystem-backed), `content_hash`, `confidence`, `note`, `created_at`.

- `coverage_summary`: normalized runtime evidence.
  - Fields: `coverage_id`, `candidate_id`, `run_id`, `tool`, `covered_functions_count`, `covered_basic_blocks_count` (nullable), `time_seconds`, `seed_count`, `crash` (bool), `crash_trace` (optional), `repro_path` (optional).

- `provenance_log`: per-run event log for audit.
  - Fields: `entry_id`, `run_id`, `severity`, `message`, `ts`.

## Required invariants
- Candidate IDs are immutable; updates create new version rows, not new IDs.
- Every artifact references both `candidate_id` and `run_id`.
- Snapshot scope is stored on the run (`module-scoped` = build graph node; `repo-wide` only when needed).
- Unknown reasons must use the taxonomy enums above; do not fall back to free text.
- Runtime evidence must include a coverage summary in the normalized fields; decompiled runs may use address-range metrics for coverage counts.

## Slicing budget handling
- On budget overflow, record fallback stage applied: `same_function_only`, `data_only`, `hop_limited`, or `abandoned`.
- If abandoned, set candidate status to `unknown_context_budget` and log reason in `provenance_log`.

## Promotion rule (triage → final)
- Promote when `risk >= high` AND (`path_depth_hint` within threshold OR dynamic evidence exists OR manual pin).
- Promotion event should be logged in `provenance_log` and reflected in an artifact note.

## Storage guidance
- Backend: SQLite with JSON columns is acceptable for local runs; PostgreSQL with JSONB for shared runs.
- Indexes: `candidate_id`, `family_id`, `run_id`, `status`, `sink_class`, `module`.
- Hashing: use lowercase paths; normalize line ranges; for decompiled anchors, include jar/binary name in the hash input.
