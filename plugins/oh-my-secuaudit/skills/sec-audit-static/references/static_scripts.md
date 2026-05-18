# Static Audit Scripts

Canonical automation scripts (repo `tools/scripts/`):

- `parse_asset_excel.py`: asset Excel -> JSON
- `merge_results.py`: merge task results -> `final_report.json`
- `ensure_metadata.py`: fill/verify required metadata fields in task JSONs
- `redact.py`: redact sensitive data in reports
- `validate_task_output.py`: schema validation for task outputs/reports
- `generate_finding_report.py`: generate Markdown report from findings
- `publish_confluence.py`: publish report to Confluence (optional)
- `scan_api.py`: API scan helper (if used)
- `scan_injection_enhanced.py`: enhanced injection scan helper (if used)
- `scan_injection_patterns.py`: injection pattern scan helper (if used)
- `scan_authkey_exposure.py`: detect auth key material exposure (`0002/getAuthkeyInfo`) and hardcoded key/iv in code/config/artifacts (supports sibling-module scan via `--extra-repo`)
- `check_finding_consistency.py`: detect wording/runtime mismatches (e.g., "without authentication" vs `*_without_auth` evidence) and mixed-category task files
- `run_zoekt_profile_and_compare.py`: one-shot Zoekt profile runner (api-max) + automatic old/new comparison report
- `code_search.sh`: code search wrapper (`zoekt` when enabled/available, `rg` fallback always)
- `extract_function_context.py`: line-hit -> function/method context extractor (tree-sitter first, fallback chain)
- `extract_endpoints_rg.py`: Spring/Kotlin endpoint inventory (rg/regex, low-cost)
- `extract_endpoints_treesitter.py`: Spring/Kotlin endpoint inventory (tree-sitter, higher precision)
- `migrate_test_groups.py`: internal migration utility (use only if needed)
- `rename_remove_prefix.py`: internal rename utility (use only if needed)
- `manage_state_store.py`: initialize and manage State Store (SQLite) for candidate/run/artifact/coverage/log data
  - Typical sequence:
    - `manage_state_store.py init --repo <path> --run-label <label>` -> record `state_store_run_id` in metadata.
    - `manage_state_store.py add-candidate --run-id <id> --candidate-id <cid> --facet '{"layer":"controller","boundary":"external","sink_class":"sql"}' --source <path:line>`
    - `manage_state_store.py add-artifact/add-coverage/add-log` to tie CPG, slices, runtime, fuzz artifacts back to candidate ID.
- `ensure_facets_and_state.py`: backfill `state_store_run_id`/`snapshot_scope` and facet tags (`layer`, `boundary`, `sink_class`) in task/finding JSONs (use after ensure_metadata + request_mapping enrichment).
- `derive_facets.py`: heuristically set facet tags from file paths before fallback to unknown_*.
- `check_versions.sh`: compare tool versions to `versions.lock` (creates it on first run).
- `check_unknowns.py`: enforce unknown_* taxonomy and require attempted steps evidence.
- `slice_context.py`: budgeted slicing around findings with overflow -> unknown_context_budget tagging.
- `rank_candidates.py`: simple heuristic ranking (severity + sink/boundary + depth).
- `high_risk_fuzz_gate.py`: pick top-K high-risk unknowns for fuzz/smoke queue.
- `lint_plan_vs_impl.sh`: quick drift/lint between plan (SKILL/references) and scripts.
- `run_static_audit.sh`: one-shot orchestrator (init state store → search → semgrep/joern hooks → slicing/facets/enrichment → validate → report), with skip flags for heavy steps and summary JSON output.
- `run_fuzz_gate.sh`: execute short real HTTP fuzz (curl-based) for queued high-risk unknowns; requires `FUZZ_BASE_URL` (or `--base-url`) and emits `coverage_*` + per-target request logs.
- `audit_slice_quality.py`: sample (default 5%) and score slice quality; outputs `slice_quality_report.json`.
- `ci_contract.sh`: CI gate using `audit_summary.json` (fail if fail_count>0 or quarantine>0).
- CI examples: `.github/workflows/static-audit-example.yml`, `.gitlab-ci.yml`.

Use only the scripts required for the target workflow; mark optional ones explicitly.

Notes:
- Task outputs must include `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules`.
- `generate_finding_report.py` 실행 시 `--source-label` 필수.
 - `generate_finding_report.py`는 task 파일 단위가 아닌 **finding.category 단위**로 섹션을 분류한다(혼합 카테고리 지원).
 - Confluence 수동 복붙/Markdown 변환 경로에서는 `--anchor-style md2cf` 사용.
 - `[[ANCHOR:...]]` (`--anchor-style confluence`)는 수동 복붙 시 매크로로 파싱되지 않고 텍스트 노출될 수 있음. 이 스타일은 `publish_confluence.py` 같은 API 게시 흐름에서만 사용.
 - Confluence 수동 복붙 시 내부 링크 안정화를 위해 `--anchor-prefix <PageTitle>`를 정확한 페이지 제목으로 지정.
 - Confluence 앵커 링크는 **헤더 텍스트 기반 자동 앵커**가 가장 안정적임.
   - `finding-<id>` 형태의 헤더를 출력하고, 실제 취약점 제목은 별도 텍스트로 표시.
   - 링크는 `#<anchor-prefix>-finding-<id>`(prefix 지정 시) 또는 `#finding-<id>`(prefix 미지정 시) 형태로 생성.
