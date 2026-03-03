# Workflow Improvement Plan v2.0 (Sec-Audit-Static)

## Scope
This document tracks the agreed improvement roadmap for `sec-audit-static`.
It is a plan/update log (not an implementation guide).

## Goal and operating principles
- Goal: accelerate source->sink reachability confirmation in large and decompiled-mixed codebases.
- Principle 1: broad retrieval first (minimize misses), narrow verification second (evidence-first).
- Principle 2: only evidence-backed minimal sliced context should reach LLM steps.
- Principle 3: all artifacts must be traceable by a single candidate ID in a central state layer.

## Priority roadmap

### Critical Review v2.1 (10 adjustments)
1. State Store operationalization: make `manage_state_store.py init/add-candidate/add-artifact/add-coverage/add-log` mandatory for every run; require run-label + snapshot_scope recorded in metadata and outputs. Add failure fallback: if state DB lock/timeouts occur, continue with JSON artifacts but emit `unknown_tooling_error` and retry queue.
2. Snapshot scope clarity: default `module` (or `decompiled-module`) must be declared up front; `repo`/`decompiled-repo` only with explicit rationale. Mixed scopes in one run are forbidden—split runs instead.
3. Edge tier logging: every edge/candidate stores source tier (`snapshot|lsp|grep`) plus confidence; Joern snapshots must be regenerated when commit hash changes; LSP/grep use only as fallback and must be flagged low-confidence.
4. Facet + request mapping enforcement: findings/candidates must carry `layer`, `boundary`, `sink_class`, and `request_mapping`; unknowns use explicit `unknown_*`; missing facets/request_mapping block promotion to report.
5. Ranking model v1.1: score = risk tier weight + sink class weight + external-input flag + inverse path depth; tie-breaker by edge confidence. Use to order verification queue; top N high-risk must get slicing + Joern confirm before report freeze.
6. Context slicing automation: LLM/reporting promotion requires backward/forward slice with budgets (max 120 lines or 1.5k tokens). Fallback ladder: same-function slice → data-only slice → 2-hop limit → mark `unknown_context_budget`.
7. Unknown taxonomy gates: a candidate may stay `unknown_*` only after (a) edge attempt, (b) slice attempt, (c) at least one verification attempt (static or runtime). Otherwise remain in triage queue.
8. Dynamic-lite + fuzz gate default: for high-risk unknowns run 10–30m fuzz/smoke; store coverage + cmd + repro in State Store. Heavy fuzz moves to batch/CI; skipping requires recorded reason.
9. Reporting propagation: merged reports and Markdown must surface facets, request_mapping, and unknown_reason; summaries should list counts by sink_class and boundary for triage.
10. QA checklist automation: pre-publish guardrail is scripted: ensure_metadata → enrich_request_mapping → ensure_facets_and_state → validate_task_output; add a CI check to block merge if any step fails.

### Critical Review v2.2 (10 additional fixes)
1. CI fail-fast thresholds: block on >0 schema/guardrail violations and on missing state_store_run_id/snapshot_scope; provide `--override` flag only for emergency with reason logged.
2. Metrics & SLOs: track per-run unknown rate, edge-confidence distribution, slice budget hit rate, fuzz coverage mins; set targets (e.g., unknown <10%, slice overflow <5%).
3. Rollback rule: if Joern snapshot is stale (commit drift) or state store write fails mid-run, invalidate the run label and rerun from snapshot build step; forbid partial merges.
4. Data retention/privacy: define TTL for State Store DB and artifacts; ensure redaction applied before exporting evidence; log PII-handling steps.
5. Parallelism guard: prevent concurrent runs writing same state store file; acquire lock or use run-id namespacing; if contention, queue or fork a new DB file.
6. Tool health check: assert joern/zoekt version and schema compatibility at start; capture versions in metadata; fail if version drift beyond tested matrix.
7. Zoekt resilience: add backoff + retry for indexing; if indexing fails, auto-fallback to rg and tag candidates with `edge_source=grep` and low confidence.
8. Slice quality audit: sample 5% of slices per run for manual/automated quality scoring; log score in State Store; trigger alert if score < threshold.
9. Fuzz gate scoping: restrict fuzz targets to top-K high-risk unknowns per run (configurable K); record skip reasons for others to avoid unbounded runtime.
10. Escape hatch for resource limits: if CPU/heap budget exceeded, pause heavy steps (joern, fuzz) and emit `indeterminate_policy`; require explicit resume command to continue.

### Critical Review v2.3 (10 execution-focused corrections)
1. End-to-end script chain: provide a single `run_static_audit.sh` that sequences init → code_search (zoekt/rg) → semgrep/joern → enrichment (request_mapping/facets/state) → validate → report; eliminates manual gaps.
2. Deterministic inputs: pin tool versions (joern, semgrep, zoekt) in the script; record versions in metadata; fail on drift vs lockfile.
3. Candidate ID stability: define canonical ID format and enforce via script; reject candidates without stable `sink_callsite_anchor`.
4. Edge/cache invalidation: automatically drop stale Joern/Zoekt indexes when commit hash changes; rebuild instead of reusing silently.
5. Auto facet derivation: add static rule-map (path/pattern → layer/boundary/sink_class) before falling back to unknown_*; reduce manual tagging.
6. Request mapping fill: make enrich step mandatory for all finding tasks (not just data_protection); fail if still missing.
7. Unknown exit criteria: before final report, any `unknown_*` must have recorded attempted steps (edge/slice/runtime) and a next action; otherwise block publish.
8. Coverage parity: require decompiled pass outputs to be compared; if missing, mark run incomplete and block report until parity achieved or reason recorded.
9. CI artifacts: publish state store, slices, logs, coverage summaries as build artifacts with TTL; ensure redaction applied.
10. Operator checklist: embed pre-publish checklist in CI output and fail if any item unchecked (snapshot_scope set, state_store_run_id set, request_mapping present, facets present, unknown_reason taxonomy used, validate passed).

### Critical Review v2.4 (10 delivery safeguards)
1. Single entrypoint ownership: one maintained script (`run_static_audit.sh`) is the only blessed path; all other runs must wrap or call it to avoid drift.
2. Lock-step doc/code: SKILL.md and script help text must be auto-checked for divergence (lint to diff key phrases like helper sequence and guardrails).
3. Failure budget: cap total wall-clock per run; if exceeded, mark run `indeterminate_policy` and require explicit resume token to continue.
4. Retry policy: search/joern/semgrep steps get bounded retries with exponential backoff; after max retries mark `unknown_tooling_error` and proceed to next steps instead of aborting whole run.
5. Partial artifact handling: if any enrichment/validate step fails for one task JSON, it should be quarantined (moved aside), but the run continues; CI fails only if quarantined items exist at end.
6. Immutable logs: provenance_log entries are append-only; no edits/deletes; include hash chain (prev_hash) to detect tampering.
7. Integrity checks: compute and store SHA256 for state JSON/artifacts in State Store; verify before report generation.
8. Default-safe skips: every `--skip-*` flag in runner must log reason + scope impact and set a metadata flag so reports show what was skipped.
9. Alerting thresholds: emit warning when unknown rate or slice overflow exceeds SLO, error when schema/guardrail fails; surface in CI summary.
10. Post-run triage queue: automatically produce a TODO list of unknowns/suspects with next-action hints (edge retry, slice budget increase, runtime probe) to prevent stall after a run.

### Critical Review v2.5 (10 no-stall reinforcements)
1. Cache invalidation proof: runner must compute repo HEAD hash and compare to stored snapshot hash; mismatch forces Joern/Zoekt rebuild before search/edges.
2. Edge confidence thresholds: forbid promotion to report if edge_source is `grep` and confidence < 0.3 unless a Joern/LSP confirmation is attached.
3. Slice budget auto-tune: if slice overflows twice, auto-increase budget up to a hard cap, else mark `unknown_context_budget` with logged cap.
4. Decompile parity gate: if decompiled pass skipped, annotate run-level metadata `decompile_status=skipped` and block “complete” status; require explicit waiver file to proceed.
5. Fuzz target cap by risk/time: enforce config `MAX_FUZZ_TARGETS` and `MAX_FUZZ_MINUTES`; beyond that emit `indeterminate_policy` with queue entry.
6. Run labeling discipline: run-label must include date + repo + scope; runner validates format and refuses otherwise to avoid collision/ambiguity.
7. Artifact TTL enforcement: runner prunes state_dir artifacts older than TTL before starting; records deletion log entries in provenance_log.
8. CI summary contract: runner outputs a machine-readable summary JSON (unknown counts, quarantined files, skips, failures); CI must parse and decide pass/fail.
9. Human override path: introduce `override_reason` flag that, when set, logs explicit human justification; report marks these items with “manual override”.
10. Continuous lint: add a fast “plan-vs-implementation” lint that checks presence of required scripts/flags and guardrail steps; fails CI if drift detected.

### Priority Replan v2.6 (ordered by impact vs effort)
1. **Edge rebuild + logging (완료)**  
   - 자동 해시 감지로 Zoekt 캐시 무효화, Joern/LSP/CSV/TSV 매핑으로 edge_source/confidence 주입, grep-only<0.3 차단 가드.
2. **Slice auto-tune (완료)**  
   - 120→200 자동 확장, overflow 시 unknown_context_budget/flow 기록.
3. **Fuzz gate execution (완료)**  
   - high_risk_fuzz_gate → run_fuzz_gate로 커버리지 JSON 생성/저장.
4. **Report surfacing (완료)**  
   - facets/unknown_reason/edge_source 표출, Sink/Boundary 요약 추가.
5. **CI contract (완료)**  
   - GitHub Actions/GitLab 예시, ci_contract.sh로 summary 검사.
6. **Decompile parity gate (완료)**  
   - run_decompile(Maven/Gradle + CFR) 실행, 게이트/waiver/summary/CI 계약 연동(waiver 시 CI 통과, 무단 스킵 시 실패).
7. **Unknown evidence autopopulate (완료)**  
   - auto_flow_notes로 slice/fuzz/Enrich 시 flow에 시도 기록.

### Priority Replan v2.7 (implemented: auth-key miss prevention)
1. **Root-cause captured**
   - Miss reason #1: single-module scope (`appif*`) hid sibling `dbif` key endpoint exposure.
   - Miss reason #2: baseline rules focused on auth-bypass/TTL, but no dedicated detector for `0002/getAuthkeyInfo` + hardcoded key/iv combo.
   - Miss reason #3: runtime evidence existed, but no deterministic bridge step to promote it into a structured task finding.
2. **Implementation fix**
   - Added `tools/scripts/scan_authkey_exposure.py` to emit task output for:
     - key-info endpoint exposure (`/appserver/0002.json`, `getAuthkeyInfo`)
     - hardcoded key/iv material in source/test/build/config artifacts
   - Added runner integration in `run_static_audit.sh` (step `[6.5]`) with optional `--extra-repo` and automatic sibling `dbif` coverage when primary repo is `appif*`.
3. **Process fix**
   - SKILL helper sequence updated to include `scan_authkey_exposure.py` before validation/report.
   - Script index updated so operators run the same detector consistently.

### Priority Replan v2.8 (implemented: mixed-category/reporting misclassification fix)
1. **Root-cause captured**
   - Misclassification reason #1: `generate_finding_report.py` previously inferred category at **task-file level** (`task_id`/filename), so mixed findings inside one task (e.g., auth/session + data-protection) were collapsed into a single section (4-x).
   - Misclassification reason #2: finding narratives used broad "without authentication" wording from static signals (`@Certification(false)`) without always reconciling runtime evidence (`*_without_auth` vs `*_with_auth`).
2. **Implementation fix**
   - Updated `generate_finding_report.py` to classify findings by **per-finding `category`** with fallback only when category is absent.
   - Added category-aware display-ID reassignment (`4-1`, `6-1`...) after aggregation so mixed task files produce correct section numbering.
   - Added `tools/scripts/check_finding_consistency.py` to warn on wording/runtime conflicts and mixed-category task files.
   - Integrated consistency check into `run_static_audit.sh` enrichment flow.
3. **Process fix**
   - SKILL helper sequence and script index updated to include `check_finding_consistency.py`.
   - Report generation note updated: mixed-category task files are now supported and must not be flattened.

### Immediate (apply first)
1. State Store layer (new)
- Introduce centralized analysis state storage keyed by candidate ID.
- Store per-layer artifacts with `version` and `timestamp`.
- Target outcome: quick root-cause lookup for `unknown` status and easier run-to-run comparison.

2. Edge layer hardening
- Make Joern CPG/call-graph snapshot the primary edge source.
- Keep LSP as secondary fallback and `rg/ctags` as tertiary fallback.
- Record edge confidence by source tier (snapshot > LSP > grep-family).

3. Context compression upgrade
- Replace simple context trimming with program slicing-based packaging.
- Apply backward/forward slicing around taint-relevant variables.
- Keep strict token/line/function budgets for reportable context packs.

4. Skill/ops documentation alignment
- Update skill references and script index to reflect new layers and execution order.
- Keep this file as plan-level summary; detailed specs stay in dedicated docs/scripts.

5. Facet minimum schema (small but mandatory)
- Add minimal facet tags during initial enrichment to improve triage quality at low cost.
- Minimum fields: `layer` (controller/service/dao/util), `boundary` (external/network/file/deserialization), `sink_class` (exec/eval/sql/fs/net/deserialize).
- Apply in Immediate scope to stabilize ranking and unknown triage from day one.

### Phase 2 (after immediate items stabilize)
1. Ranking model upgrade
- Expand ranking with risk score and reachability depth hint.
- Prioritize external input + high-risk sinks + shorter path length.

2. Fuzz operations model
- Default to short fuzz gate (10-30m) for high-risk unknowns.
- Move heavier fuzz to batch/CI.
- Keep symbolic execution as optional escalation for satisfiability checks.

## Layer model snapshot (v2.0)
0. Principles and traceability baseline  
0.5. State Store (new)  
1. Retrieval  
2. Facet enrichment  
3. Edge construction (snapshot-first)  
4. Ranking (risk + depth aware)  
5. Static verification (Semgrep/Joern)  
6. Dynamic-lite verification  
7. Fuzz verification (ops-gated)  
8. Context compression (program slicing)  
9. Reporting  
10. Skill/state management

## Operating invariants (must hold)
1. Candidate identity definition
- A candidate is anchored by a stable sink callsite and grouped with variable entry/source clusters.
- Recommended identity model: `candidate_family = sink_callsite_anchor`, `candidate_instance = family + source_cluster`.
- Anchor minimum shape: `sink_callsite_anchor = (repo, path, function, line_range, sink_symbol_or_api)`.
- Decompiled fallback key is allowed when line fidelity is weak: `address` or `basic_block_id`.
- Goal: preserve run-to-run diff stability while allowing source-side evolution.

2. Unknown status taxonomy
- Do not use a single `unknown` bucket. Store one of:
- `unknown_no_edges`
- `unknown_dynamic_dispatch`
- `unknown_context_budget`
- `unknown_needs_runtime`
- `unknown_tooling_error`
- Additional terminal states allowed when justified:
- `indeterminate_policy` (policy/environment prevents further verification)
- `benign_unreachable` (evidence-backed practical non-reachability)
- Goal: make blockage reasons queryable and prioritizable in State Store metrics.

3. Edge snapshot scope rule
- Define snapshot scope explicitly per run: `module-scoped` by default, `repo-wide` only when needed.
- `module-scoped` means a build graph node (for example: Maven module, Gradle subproject, JS workspace package, C/C++ build target, or decompiled binary unit).
- Decompiled artifacts use separate snapshot namespace and are linked by mapping metadata.
- Goal: prevent confidence drift and keep comparisons reproducible.

4. Slicing trigger rule
- Program slicing is mandatory for candidates promoted to LLM/reporting stages.
- Optional for lower-priority triage candidates to control compute cost.
- Recommended triggers: high-risk tier, top ranked paths, or candidates entering final verification.
- On slicing budget overflow, apply fallback sequence:
- (a) same-function-only slice
- (b) data-only slice (drop control-flow expansion)
- (c) reduced hop depth (for example, max 2-hop)
- If still over budget, close with `unknown_context_budget` and store reason.

5. Dynamic/fuzz evidence minimum set
- Every runtime verification artifact must bind to candidate ID with:
- command line, input/seed reference, coverage summary, crash/stacktrace (if any), repro script/location.
- Coverage summary should include normalized minimal fields:
- `covered_functions_count`, `covered_basic_blocks_count` (if available), `time_seconds`, `seed_count`.
- Decompiled/runtime-limited environments may use equivalent address-range coverage metrics.
- Goal: keep runtime checks auditable and report-ready.

## Reporting outputs split
- Triage output: ranked candidates, edge confidence, unknown reason codes.
- Final output: evidence chain, sliced context, reachability verdict, and reproduction evidence.
- Both outputs remain linked by candidate ID.
- Promote candidate from triage to final when:
- `risk >= high` and at least one of: bounded path depth threshold met, dynamic evidence exists, or manual pin is recorded.

## Facet tagging rule
- `layer`, `boundary`, and `sink_class` must always be present.
- If classification is uncertain, use explicit unknown values (`unknown_layer`, `unknown_boundary`, `unknown_sink_class`) instead of omission.
- Store short tagging evidence in State Store (rule id, API symbol, or path-pattern basis).

## Expected impact
- Reliability: stronger edge confidence and fewer unresolved candidates.
- Throughput: less redundant manual tracing for large repositories.
- Explainability: each verdict is auditable from candidate ID to evidence chain.
- Maintainability: workflow changes become versioned and diff-friendly.

## Notes
- Zoekt-based prefiltering and `rg` fallback policy remain valid and unchanged.
- Existing decompiled-pass parity requirement remains valid and unchanged.
- This plan intentionally avoids low-level schema/script details; those are maintained in dedicated references and tools.
- State Store schema/details are tracked in `references/state_store_spec.md` (draft).
- Auth/Proxy detection plan (applicable across modules):
  - Detect auth-bypass patterns: `@Certification(false)` or whitelist arrays; prefer default-deny with explicit allow.
  - Extract authKey TTL; warn if >24h.
  - Flag external-call hubs (CommonIF subclasses, DBIF/GW callers) with sink_class updates; prioritize those touching sensitive fields.
  - SSRF/proxy checks: input `host/url` -> HTTP client; require allowlist + internal/metadata IP block.
  - Dynamic smoke (allowlisted URLs only): unauthenticated requests should return 401/403.
  - Reporting: confirm high-risk suspects only; bulk external-call suspects listed separately; remove placeholders.
- Auth/key-specific auto rules:
  - Mark `@Certification(false)` as high risk when class/remarks include “인증 후/secure/key”.
  - Detect auth exceptions hardcoded by command (e.g., 5659/5650/5513/5616/5250) and flag.
  - Detect authKey TTL > 24h constants (e.g., `getDatewithGap(50)`) and emit warning.
  - Detect responses containing key/secret/token/memberId/mdn/ci/birthday or `putAll` of external API responses without filtering.
  - Sensitive-field logging check: mdn/ci/memberId in logs.
