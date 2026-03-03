# State Store Wiring Order (Sequential)

Purpose: step-by-step wiring of existing pipeline stages to the State Store using `manage_state_store.py`. Follow the order; skip steps that are out of scope for a given run.

## 0) Prep
- DB: `python3 tools/scripts/manage_state_store.py --db state_store.db init`
- Common flags: `--db state_store.db`
- Snapshot scope: `module-scoped` by default (build graph node); use `--snapshot-scope repo-wide` only if necessary.

## 1) Retrieval (code_search / Zoekt / rg)
1. Add run
   - `run_id=$(python3 tools/scripts/manage_state_store.py --db state_store.db add-run --tool code_search --command "<cmd>" --snapshot-scope module-scoped --snapshot-name retrieval)`
2. Add artifact (search results file)
   - `python3 tools/scripts/manage_state_store.py --db state_store.db add-artifact --candidate-id <cid-or-placeholder> --run-id $run_id --layer retrieval --type json --path state/retrieval_candidates.json --note "code_search results"`  
   - If candidates not yet created, use placeholder `candidate_id=placeholder_retrieval` and replace later with `update-candidate`.

## 2) Facet enrichment
1. Add/Update candidates with facet fields (layer/boundary/sink_class; allow `unknown_*`).
   - `python3 tools/scripts/manage_state_store.py --db state_store.db add-candidate --hash-anchor --repo <repo> --module <mod> --path <file> --function <fn> --line-range <start-end> --sink-symbol-or-api <sink> --layer controller --boundary external --sink-class net --status unknown_no_edges`
2. Special handling: common interface / service hubs
   - Detect hubs (`CommonIF`, `*Service`, `*Processor`).
   - Facets: `layer=service`, `boundary=internal`, `sink_class=app_logic`, note `common-entry`.
   - Enrich sink_class/boundary from downstream evidence:
     - If hub calls DB/mapper: set `sink_class=sql`, `boundary=internal`.
     - If hub calls outbound HTTP/RestTemplate/Feign: `sink_class=net`, `boundary=external`.
     - If hub does file/crypto: `sink_class=fs`/`data`.
   - When controller → common-entry call is detected, create/upgrade the hub candidate to `suspect` even if controller is a delegator.
3. Artifact: enriched facets file (if generated)
   - `python3 tools/scripts/manage_state_store.py --db state_store.db add-artifact --candidate-id <cid> --run-id <facet_run_id> --layer facet --type json --path state/facets_enriched.json`

## 3) Edge construction (Joern snapshot-first, LSP, grep fallback)
1. Run record
   - `run_id=$(python3 tools/scripts/manage_state_store.py --db state_store.db add-run --tool joern --command "<joern-cmd>" --snapshot-scope module-scoped --snapshot-name edge)`
2. Artifact: edges file
   - `python3 tools/scripts/manage_state_store.py --db state_store.db add-artifact --candidate-id <cid> --run-id $run_id --layer edge --type json --path state/graph_edges.json --note "confidence tiers snapshot>LSP>grep"`
3. Update candidate status if edges found
   - `python3 tools/scripts/manage_state_store.py --db state_store.db update-candidate <cid> --status suspect --rank-hint <float> --path-depth-hint <float>`

## 4) Ranking (risk + depth)
1. Run record
   - `run_id=$(python3 tools/scripts/manage_state_store.py --db state_store.db add-run --tool rank --command "<ranking-cmd>" --snapshot-scope module-scoped --snapshot-name ranking)`
2. Artifact
   - `python3 tools/scripts/manage_state_store.py --db state_store.db add-artifact --candidate-id <cid> --run-id $run_id --layer rank --type json --path state/ranked_paths.json`
3. Update candidate scores
   - `python3 tools/scripts/manage_state_store.py --db state_store.db update-candidate <cid> --risk-score <float> --rank-hint <float> --path-depth-hint <float>`

## 5) Static verification (Semgrep/Joern)
1. Run record (per tool if separate)
   - `run_id=$(python3 tools/scripts/manage_state_store.py --db state_store.db add-run --tool semgrep --command "<semgrep-cmd>" --snapshot-scope module-scoped --snapshot-name static)`
2. Artifact: results file
   - `python3 tools/scripts/manage_state_store.py --db state_store.db add-artifact --candidate-id <cid> --run-id $run_id --layer static --type json --path state/semgrep_results.json --note "static verification"`
3. Candidate status update on confirmation
   - `update-candidate <cid> --status reachable` (or keep `suspect`/`unknown_*` with reason)

## 6) Dynamic-lite
1. Run record
   - `run_id=$(python3 tools/scripts/manage_state_store.py --db state_store.db add-run --tool dynamic-lite --command "<cmd>" --snapshot-scope module-scoped --snapshot-name dynamic)`
2. Artifact: logs/evidence
   - `add-artifact ... --layer dynamic --path state/dynamic_logs.txt`
3. Coverage summary (normalized)
   - `manage_state_store.py add-coverage --candidate-id <cid> --run-id $run_id --tool <tool> --covered-functions-count <n> --covered-basic-blocks-count <n?> --time-seconds <t> --seed-count <s> [--crash --crash-trace <trace> --repro-path <path>]`

## 7) Fuzz (batch gate)
1. Run record
2. Artifact: fuzz results
3. Coverage summary (same schema as above)
4. Status: update to `reachable` or keep `unknown_*`; mark `benign_unreachable` if evidence-backed non-reachability.

## 8) Slicing / Context compression
1. Run record
2. Artifact: `state/context_pack.json` (or sliced snippet file)
3. On budget overflow: follow fallback sequence; if abandoned, set status `unknown_context_budget` and log reason.

## 9) Reporting
1. Run record for report generation
2. Artifact: Markdown/JSON report paths
3. Promotion rule: promote triage → final when `risk >= high` and (`path_depth_hint` within threshold OR dynamic evidence exists OR manual pin).

## 10) Logging & provenance
- Use `add-log` for significant events (skip list churn).
- Severity: `info|warn|error`.
- Example: `python3 tools/scripts/manage_state_store.py --db state_store.db add-log --run-id $run_id --severity warn --message "slicing budget overflow; applied same-function-only"`
