---
name: sec-audit-static
description: Static code security audit playbook (SAST, SCA, secret detection) with standardized JSON outputs and reporting. Use for source-code based assessments, schema validation, and generating final reports.
---

# Sec Audit Static

## Overview
Run the static audit workflow for a codebase: asset identification, API inventory, SAST-style reviews, SCA/secret checks (Gitleaks-first), and report generation using the existing schemas and scripts.

## Self-contained layout (installed skill)
When installed under `~/.codex/skills/local/sec-audit-static`, the skill is fully self-contained:
- `tools/` (scripts)
- `schemas/`
- `references/`
- `SEVERITY_CRITERIA_DETAIL.md` and reporting config files

You can run scripts from any working directory by invoking the script path directly, e.g.
`~/.codex/skills/local/sec-audit-static/tools/scripts/scan_api.py --repo <target> ...`.

## Workflow
1. Load playbook references:
- `references/static_sources.md` for the canonical docs/prompts/schemas locations.
- `references/static_scripts.md` for available automation entrypoints.
- `references/severity_criteria.md` plus `SEVERITY_CRITERIA_DETAIL.md` for risk mapping (5->Critical ... 1->Info).
- `references/reporting_summary.md` for the cross-skill summary index format.
- `references/dependency_audit.md` for internal dependency checks when requested.
- `references/seed_usage.md` for semgrep/joern seed usage rules (2-3/2-4/2-5/2-6).
- `references/poc_policy.md` for best-effort PoC generation rules.
- `references/env_setup.md` for Docker-preferred environment setup.
- `references/verification_policy.md` for commit-specific remediation checks.
- `references/taint_tracking.md` for Source->Sink confirmation and rule generation.
- `references/rule_validation.md` for mandatory post-rule validation.
- `references/tooling.md` for code-browser tooling (rg/ctags).
- `references/zoekt_workflow.md` for optional Zoekt-based candidate scoping and fallback rules.
- `references/vuln_automation_principles.md` for discovery/analysis split and hypothesis loop.
- `references/global_filters.md` for global filter/interceptor verification.
- `references/workflow_comparison.md` for before/after operating model deltas.
2. Execute tasks in order:
- State Store init + snapshot scope:
  - Initialize state store for the run: `tools/scripts/manage_state_store.py init --repo <path> --run-label <label>` and record the returned `state_store_run_id` in metadata.
  - Declare snapshot scope in metadata (`snapshot_scope=module` by default; `repo` only when needed). Use separate namespace for decompiled artifacts.
- Phase 1: asset identification.
- Phase 1.0: If wiki publishing is expected, capture Confluence page title (exact case) or pageId before analysis to build anchors.
  - If only a page URL is provided, resolve `pageId` via Confluence REST API first.
  - Use `.env` values: `CONFLUENCE_BASE_URL`, `CONFLUENCE_SPACE_KEY`, `CONFLUENCE_PAT` (or `CONFLUENCE_TOKEN`).
  - Example (title known): `GET $CONFLUENCE_BASE_URL/rest/api/content?spaceKey=$CONFLUENCE_SPACE_KEY&title=<URL-encoded-title>&type=page&expand=version`
  - Example (title uncertain): `GET $CONFLUENCE_BASE_URL/rest/api/content/search?cql=space=$CONFLUENCE_SPACE_KEY%20AND%20title~%22<keyword>%22`
  - Record resolved `pageId` and exact title in metadata for report anchors/publishing.
- Phase 1.5 (candidate scoping, optional but recommended for large repos):
  - Use `tools/scripts/code_search.sh` with `--engine auto` and `ZOEKT_ENABLED=1` when Zoekt is available.
  - Scope by sink/source patterns first, then pass narrowed file sets into Semgrep/Joern.
  - Fallback is mandatory: if Zoekt is unavailable or query/index fails, continue with `rg` without blocking analysis.
  - For repeatable coverage-first runs, use `tools/scripts/run_zoekt_profile_and_compare.py` (api-max fixed profile + auto comparison artifact generation).
  - Rank candidates early by risk (external input + high-risk sink) and approximate path depth; push top-ranked to verification queue first.
  - Apply facet tagging at candidate creation: set `layer` (controller/service/dao/util), `boundary` (external/network/file/deserialization), and `sink_class` (exec/eval/sql/fs/net/deserialize). If unknown, use explicit `unknown_*` values.
- Edge layer hardening:
  - Build Joern CPG/call-graph snapshot as primary edge source; record edge source tier (`snapshot`|`lsp`|`grep`) per edge/candidate.
  - Use LSP as secondary fallback, `rg/ctags` as tertiary. Do not block on higher-tier failures—log the fallback.
- Context compression (slicing):
  - For candidates promoted to LLM/reporting, package context via backward/forward slicing around taint-relevant vars/functions with strict token/line budgets.
  - On budget overflow, fall back in order: same-function-only slice → data-only slice (no control-flow expansion) → reduced hop depth (max 2-hop). If still over budget, mark `unknown_context_budget` in state store and metadata.
- Phase 2: API inventory (script-first), then confirm global filters/interceptors, then parallel reviews (injection/XSS/file handling/data protection).
- Phase 2 guardrail (cross-module): if auth/session boundary spans sibling modules (for example `appif*` + `dbif`), run a dedicated key-exposure scan across both modules and include results in task outputs.
- For API inventory, if FindSecBugs is executed and `SPRING_ENDPOINT` results exist, compare controller classes with inventory results. Record any class-level mismatches and note that FindSecBugs lacks URL patterns (class-only comparison).
- Phase 2.5 (mandatory for buildable JVM services): Build and decompile artifacts to create a decompiled source snapshot, then run the same audit pipeline on the decompiled output and compare results. New findings from decompiled analysis must be mapped back to source paths when possible, and reported as additional findings.
  - Build: use the repo’s standard build (`./gradlew clean assemble -x test` or `mvn -q -DskipTests package`).
  - Decompile: prefer CFR (`cfr-0.152.jar`) for WAR/JAR; output to `<repo>/decompiled`.
  - Run the same discovery and flow-confirmation stack on decompiled output (`code_search -> Semgrep -> Joern`) and compare with source pass.
  - Limit decompiled scope to the main package (e.g., `com/skp/ocb/api`) for performance.
  - Only skip Phase 2.5 if build/decompile is technically impossible (missing build tooling, irrecoverable build errors, or binary artifacts unavailable). Record the reason explicitly in metadata.
- Mandatory (JVM buildable): run Semgrep on the **decompiled** output using the same rule set (record findings + output path in metadata).
- Add SCA and secret detection as part of Phase 2 when configured. Use Gitleaks as the primary secret scanner.
- Request-mapping enrichment (before reporting): populate `request_mapping` in finding JSONs from controller constants when URLs are not already present. Use the repo’s helper if available, e.g. `python tools/enrich_request_mapping.py state/task_25_result.json src/main/java/.../ControllerConst.kt`. Rerun on any regenerated task JSONs.
- Unknown taxonomy: classify non-verified candidates as one of `unknown_no_edges`, `unknown_dynamic_dispatch`, `unknown_context_budget`, `unknown_needs_runtime`, `unknown_tooling_error`, `indeterminate_policy`, or `benign_unreachable` instead of a generic `unknown`.
- Injection review rule: if you cannot prove a Source→Sink SQL injection flow, you must still record **suspected candidates** (file:line + reason) in the task notes/metadata. Do not mark them as confirmed findings unless a clear Source→Sink path is demonstrated.
- For every confirmed finding, you must record a **code/input flow** in the finding JSON as `flow` (list of steps). If the flow cannot be determined, record a single-step flow explaining why (e.g., "flow not determined: insufficient call-chain context"). Do not omit flow in reports.
- For any confirmed finding, you must create or update Semgrep/Joern rules (unless explicitly waived by the user).
- After rule updates, re-run seed generation and re-check affected phases before finalizing outputs.
- For 2-2 (injection), if the codebase uses SQL/JDBC/R2DBC, always check for dynamic SQL assembly patterns (`toSql`, `String.format`, string concatenation, template SQL) even if seeds are empty.
 - Do not use CodeQL. Use Joern for flow-based checks.
- For JVM services, run FindSecBugs (SpotBugs + FindSecBugs rules) after a successful build. Record execution status, command, summary (finding count), and output path in metadata. If tooling is unavailable, record the reason and follow-up action.
- Dynamic-lite + fuzz gate (high-risk unknowns): run a short fuzz gate (10–30m) for high-risk unknowns; heavier fuzz moves to batch/CI. Every runtime artifact must bind to candidate ID and include command, inputs/seeds, coverage summary, crash/stacktrace (if any), repro script/location.
3. Produce outputs in JSON matching the schemas.
   - Every task output **must** include `metadata.source_repo_url`, `metadata.source_repo_path`, and `metadata.source_modules`.
   - If a wiki report is published, include `metadata.report_wiki_url` and set `metadata.report_wiki_status`.
- Guardrail: ensure every finding has `request_mapping` populated (run the enrichment helper if empty) and rerun `tools/scripts/validate_task_output.py`.
- Guardrail: ensure every finding includes facet tags `layer`, `boundary`, `sink_class` (use `unknown_*` when uncertain) and store short tagging evidence in state store.
- Guardrail: ensure every candidate/finding has `snapshot_scope` and `state_store_run_id` in metadata.
- Guardrail: unknown classification must use the defined taxonomy (no generic `unknown`).
- **Guardrail:** before merging or reporting, verify all task JSONs contain the required `metadata.*` fields. If any are missing, stop and populate them (prefer the actual audited repo path/URL), then re-run `tools/scripts/validate_task_output.py`.
- Helper sequence before final report: run `ensure_metadata.py`, `enrich_request_mapping.py`, `derive_facets.py`, `ensure_facets_and_state.py`, `slice_context.py`, `scan_authkey_exposure.py` (when auth-key material exists), `check_finding_consistency.py` (wording/runtime/category consistency), `check_unknowns.py`, `validate_task_output.py`, `rank_candidates.py`, `high_risk_fuzz_gate.py`.
- End-to-end runner: `tools/scripts/run_static_audit.sh --repo <path> --state-dir <state> --run-label <label> [--snapshot-scope module|repo|decompiled-module|decompiled-repo]` (version check, TTL prune, state store init, search, semgrep/joern hooks, slicing/facet/enrichment, validation, summary JSON; heavy steps skippable with flags; override flag for emergency).
4. Generate final report and validate:
- `tools/scripts/merge_results.py`
- `tools/scripts/redact.py`
- `tools/scripts/validate_task_output.py`
5. Generate Markdown report (required):
- `tools/scripts/generate_finding_report.py`
   - Always pass `--source-label` (use repo URL or a user-facing path label).
   - Confluence 수동 복붙(에디터 Markdown 변환) 경로는 `--anchor-style md2cf`를 사용한다. `confluence` 스타일(`[[ANCHOR:...]]`)은 수동 복붙 시 일반 텍스트로 노출될 수 있다.
   - Confluence 링크가 필요하면 `--anchor-prefix <PageTitle>`를 **정확한 페이지 제목 그대로** 전달한다. 스크립트가 이를 Confluence 헤더 ID 규칙(소문자 + 비영문자 제거)으로 정규화해 링크를 생성한다.
   - Confluence API 게시(`publish_confluence.py`) 전용 흐름에서만 `confluence` 스타일 앵커를 사용한다.
   - Include suspected SQLi candidates section when present in task metadata.
- Ensure subcategory classification is validated (e.g., NoSQL vs SQL) after report generation.

## Reporting
- Primary output: task JSONs + `final_report.json` + Markdown report.
- Use severity mapping from `references/severity_criteria.md` and detailed criteria in `skills/SEVERITY_CRITERIA_DETAIL.md`.
- Produce a common summary JSON using `schemas/reporting_summary_schema.json`.

## Resources
### scripts/
Use the existing automation scripts from the repo (see `references/static_scripts.md`).
- State Store management: `tools/scripts/manage_state_store.py` (`init`, `add-run`, `add-candidate`, `add-artifact`, `add-coverage`, `add-log`).

### references/
- `references/static_sources.md`
- `references/static_scripts.md`
- `references/severity_criteria.md`
- `references/reporting_summary.md`
- `references/dependency_audit.md`
- `references/seed_usage.md`
- `references/poc_policy.md`
- `references/env_setup.md`
- `references/verification_policy.md`
- `references/taint_tracking.md`
- `references/rule_validation.md`
- `references/tooling.md`
- `references/workflow_comparison.md`
- `references/zoekt_workflow.md`
- `references/state_store_spec.md` (State Store schema/invariants)
- `references/state_store_wiring.md` (State Store wiring order and command templates)

- Include code evidence blocks in findings using the format: FILE + fenced snippet with line numbers.
