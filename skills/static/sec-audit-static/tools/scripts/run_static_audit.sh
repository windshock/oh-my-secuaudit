#!/usr/bin/env bash
# Orchestrated static audit runner with guardrails and no-stall checks.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --repo <path> --state-dir <path> --run-label <label> [--snapshot-scope module|repo|decompiled-module|decompiled-repo] [--lock-file versions.lock]
         [--extra-repo <path>]...
Flags: [--skip-search] [--skip-semgrep] [--skip-joern] [--skip-decompiled] [--skip-report]
       [--ttl-days <N>] [--max-retries <N>] [--override-reason <text>]
EOF
}

REPO=""
STATE=""
LABEL=""
SCOPE="module"
LOCK_FILE=""
SKIP_SEARCH=0
SKIP_SEMGREP=0
SKIP_JOERN=0
SKIP_DECOMP=0
SKIP_REPORT=0
MAX_RETRIES=2
TTL_DAYS=30
OVERRIDE_REASON=""
DECOMPILE_WAIVER=""
EDGE_CSV=""
EXTRA_REPOS=()
DECOMP_STATUS="done"
DECOMPILE_SCRIPT="$(cd "$(dirname "$0")" && pwd)/run_decompile.sh"
SEARCH_QUERY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --state-dir) STATE="$2"; shift 2;;
    --run-label) LABEL="$2"; shift 2;;
    --snapshot-scope) SCOPE="$2"; shift 2;;
    --lock-file) LOCK_FILE="$2"; shift 2;;
    --skip-search) SKIP_SEARCH=1; shift;;
    --skip-semgrep) SKIP_SEMGREP=1; shift;;
    --skip-joern) SKIP_JOERN=1; shift;;
    --skip-decompiled) SKIP_DECOMP=1; shift;;
    --skip-report) SKIP_REPORT=1; shift;;
    --max-retries) MAX_RETRIES="$2"; shift 2;;
    --ttl-days) TTL_DAYS="$2"; shift 2;;
    --override-reason) OVERRIDE_REASON="$2"; shift 2;;
    --decompile-waiver) DECOMPILE_WAIVER="$2"; shift 2;;
    --edge-csv) EDGE_CSV="$2"; shift 2;;
    --search-query) SEARCH_QUERY="$2"; shift 2;;
    --extra-repo) EXTRA_REPOS+=("$2"); shift 2;;
    *) usage; exit 1;;
  esac
done

[[ -z "$REPO" || -z "$STATE" || -z "$LABEL" ]] && { usage; exit 1; }
# run-label discipline: YYYYMMDD-<repo>-<scope>
if ! [[ "$LABEL" =~ ^[0-9]{8}-.+-[A-Za-z0-9_-]+$ ]]; then
  echo "run-label must match YYYYMMDD-<repo>-<scope>; got '$LABEL'" >&2
  exit 1
fi

mkdir -p "$STATE"
cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)/../.."
LOCK_FILE="${LOCK_FILE:-$ROOT/versions.lock}"

echo "[1] version check"
bash "$ROOT/tools/scripts/check_versions.sh" "$LOCK_FILE"

# TTL prune
echo "[2] prune state dir older than ${TTL_DAYS}d"
find "$STATE" -type f -mtime +"$TTL_DAYS" -print -delete 2>/dev/null | sed 's/^/pruned: /' || true

DB="$STATE/state_store.db"
echo "[3] state store init"
python "$ROOT/tools/scripts/manage_state_store.py" --db "$DB" init >/dev/null

echo "[4] add run"
RUN_ID=$(python "$ROOT/tools/scripts/manage_state_store.py" --db "$DB" add-run --tool run_static_audit --command "$0 $*" --snapshot-scope "$SCOPE" --snapshot-name "$LABEL")
echo "RUN_ID=$RUN_ID"

log() { python "$ROOT/tools/scripts/manage_state_store.py" --db "$DB" add-log --run-id "$RUN_ID" --message "$1" >/dev/null || true; }
warn() { python "$ROOT/tools/scripts/manage_state_store.py" --db "$DB" add-log --run-id "$RUN_ID" --severity warn --message "$1" >/dev/null || true; }
err() { python "$ROOT/tools/scripts/manage_state_store.py" --db "$DB" add-log --run-id "$RUN_ID" --severity error --message "$1" >/dev/null || true; }

fail_count=0
quarantine=()
skips=()

# repo hash check for cache invalidation
HEAD_HASH="no-git"
if [[ -d "$REPO/.git" ]]; then
  HEAD_HASH=$(cd "$REPO" && git rev-parse HEAD 2>/dev/null || echo "unknown")
  if [[ -f "$STATE/snapshot.hash" ]]; then
    prev_hash=$(cat "$STATE/snapshot.hash")
    if [[ "$prev_hash" != "$HEAD_HASH" ]]; then
      warn "snapshot hash mismatch (prev $prev_hash != current $HEAD_HASH); invalidating caches"
      rm -f "$STATE"/joern_snapshot* "$STATE"/zoekt.index || true
      fail_count=$((fail_count+1))
    fi
  fi
  echo "$HEAD_HASH" > "$STATE/snapshot.hash"
fi

echo "[5] candidate scoping"
if [[ $SKIP_SEARCH -eq 0 ]]; then
  if [[ -z "$SEARCH_QUERY" ]]; then
    warn "search query not provided; skipping search"
  else
    attempt=0; success=0
    while [[ $attempt -le $MAX_RETRIES ]]; do
      if ZOEKT_REBUILD=auto SNAPSHOT_HASH="$HEAD_HASH" bash "$ROOT/tools/scripts/code_search.sh" --engine auto --repo "$REPO" --query "$SEARCH_QUERY"; then
        success=1; break
      fi
      attempt=$((attempt+1))
      warn "code_search attempt $attempt failed; retrying with backoff"
      sleep $((attempt*2))
    done
    if [[ $success -eq 0 ]]; then
      err "code_search failed; fallback to rg"
      bash "$ROOT/tools/scripts/code_search.sh" --engine rg --repo "$REPO" --query "$SEARCH_QUERY" || true
      fail_count=$((fail_count+1))
    fi
  fi
else
  log "code_search skipped"; skips+=("search")
fi

echo "[6] semgrep/joern"
if [[ $SKIP_SEMGREP -eq 0 ]]; then
  # Run endpoint-aware injection scan using existing API inventory
  if ! python "$ROOT/tools/scripts/scan_injection_enhanced.py" "$REPO" --api-inventory "$STATE/task_21_api_inventory.json" --output "$STATE/task_22_injection_enhanced.json" --search-query "$SEARCH_QUERY" 2>/dev/null; then
    warn "semgrep failed"; fail_count=$((fail_count+1))
  fi
  log "semgrep attempted"
else
  log "semgrep skipped"; skips+=("semgrep")
fi
if [[ $SKIP_JOERN -eq 0 ]]; then
  if ! python "$ROOT/tools/scripts/scan_injection_patterns.py" "$REPO" --output "$STATE/task_22_injection_patterns.json" 2>/dev/null; then
    warn "joern seeds failed"; fail_count=$((fail_count+1))
  else
    python "$ROOT/tools/scripts/manage_state_store.py" --db "$DB" add-artifact --candidate-id "RUN" --run-id "$RUN_ID" --layer "edges" --type "joern" --path "$STATE/joern_snapshot.bin" --edge-source "snapshot" --confidence 0.9 --note "joern snapshot marker" >/dev/null || true
    python "$ROOT/tools/scripts/edge_confidence_apply.py" "$STATE"/task_*_result.json --edge-source snapshot --confidence 0.9 || true
    if [[ -n "$EDGE_CSV" && -f "$EDGE_CSV" ]]; then
      python "$ROOT/tools/scripts/apply_edge_confidence_from_csv.py" "$EDGE_CSV" "$STATE"/task_*_result.json || true
    elif [[ -f "$STATE/joern_taint_results.tsv" ]]; then
      python "$ROOT/tools/scripts/apply_edge_confidence_from_joern.py" "$STATE/joern_taint_results.tsv" "$STATE"/task_*_result.json || true
    fi
    if [[ -f "$STATE/lsp_edges.tsv" ]]; then
      python "$ROOT/tools/scripts/apply_edge_confidence_from_lsp.py" "$STATE/lsp_edges.tsv" "$STATE"/task_*_result.json || true
    fi
    python "$ROOT/tools/scripts/edge_confidence_merge.py" "$STATE"/task_*_result.json --state-dir "$STATE" ${EDGE_CSV:+--edge-csv "$EDGE_CSV"} || true
  fi
  log "joern seeds attempted"
else
  log "joern skipped"; skips+=("joern")
fi

echo "[6.5] auth/key exposure scan"
AUTH_SCAN_ARGS=(
  --repo "$REPO"
  --output "$STATE/task_26_result.json"
  --state-store-run-id "$RUN_ID"
  --snapshot-scope "$SCOPE"
)
for extra_repo in "${EXTRA_REPOS[@]}"; do
  AUTH_SCAN_ARGS+=(--extra-repo "$extra_repo")
done
if ! python "$ROOT/tools/scripts/scan_authkey_exposure.py" "${AUTH_SCAN_ARGS[@]}"; then
  warn "scan_authkey_exposure failed"
  fail_count=$((fail_count+1))
else
  log "scan_authkey_exposure completed"
fi

echo "[7] decompiled pass"
if [[ $SKIP_DECOMP -eq 0 ]]; then
  if [[ -x "$DECOMPILE_SCRIPT" ]]; then
    if "$DECOMPILE_SCRIPT" --repo "$REPO" --state-dir "$STATE"; then
      log "decompile success"
    else
      warn "decompile failed"
      DECOMP_STATUS="failed"
      fail_count=$((fail_count+1))
    fi
  else
    warn "decompile script missing; set --skip-decompiled or provide waiver"
    DECOMP_STATUS="failed"
    fail_count=$((fail_count+1))
  fi
else
  log "decompiled pass skipped"; skips+=("decompiled")
  DECOMP_STATUS="skipped"
  if [[ -z "$DECOMPILE_WAIVER" || ! -f "$DECOMPILE_WAIVER" ]]; then
    err "decompile parity gate triggered (skipped without waiver)"
    if [[ -z "$OVERRIDE_REASON" ]]; then exit 1; else warn "override applied: $OVERRIDE_REASON"; fi
  else
    warn "decompile skipped with waiver: $DECOMPILE_WAIVER"
    DECOMP_STATUS="waived"
  fi
fi
export DECOMP_STATUS_ENV="$DECOMP_STATUS"

echo "[8] enrichment (request_mapping + facets + state)"
python "$ROOT/tools/enrich_request_mapping.py" "$STATE/task_25_result.json" "$REPO/src/main/java/com/skp/wallet/appif/v1/core/controller/ControllerConst.kt" 2>/dev/null || true
python "$ROOT/tools/scripts/derive_facets.py" "$STATE"/task_*_result.json 2>/dev/null || true
python "$ROOT/tools/scripts/ensure_facets_and_state.py" "$STATE"/task_*_result.json --state-store-run-id "$RUN_ID" --snapshot-scope "$SCOPE" || true
python "$ROOT/tools/scripts/slice_context.py" "$STATE"/task_*_result.json --repo "$REPO" --state-dir "$STATE" || true
if [[ -d "$STATE/slices" ]]; then
  python "$ROOT/tools/scripts/audit_slice_quality.py" --slices-dir "$STATE/slices" --sample-rate 0.05 --min-samples 1 --output "$STATE/slice_quality_report.json" || true
fi
python "$ROOT/tools/scripts/rank_candidates.py" "$STATE"/task_*_result.json || true
python "$ROOT/tools/scripts/high_risk_fuzz_gate.py" "$STATE"/task_*_result.json --out "$STATE/fuzz_queue.json" || true
python "$ROOT/tools/scripts/auto_flow_notes.py" "$STATE"/task_*_result.json --note "slice: generated" --note "enrich: request_mapping/facets/state" || true
python "$ROOT/tools/scripts/check_finding_consistency.py" "$STATE"/task_*_result.json --runtime-evidence-dir "$STATE/runtime_evidence" || true
if [[ -f "$STATE/fuzz_queue.json" ]]; then
  MAX_TOTAL_SEC=1800 PER_TARGET=600 bash "$ROOT/tools/scripts/run_fuzz_gate.sh" --queue "$STATE/fuzz_queue.json" --state-dir "$STATE" --run-id "$RUN_ID" || warn "fuzz gate failed"
  python "$ROOT/tools/scripts/auto_flow_notes.py" "$STATE"/task_*_result.json --note "runtime: fuzz attempted" || true
fi

echo "[9] validate"
shopt -s nullglob
for f in "$STATE"/task_*_result.json "$STATE"/task_*_api_inventory.json; do
  if ! python "$ROOT/tools/scripts/validate_task_output.py" "$f"; then
    warn "validate failed: $f"
    quarantine+=("$f")
  fi
done
shopt -u nullglob
if ! python "$ROOT/tools/scripts/check_unknowns.py" "$STATE"/task_*_result.json 2>/dev/null; then
  warn "unknown check failed"
  fail_count=$((fail_count+1))
fi

# Enforce edge confidence: grep-only with low confidence blocks report
low_conf=0
for f in "$STATE"/task_*_result.json; do
  if [[ -f "$f" ]]; then
    if jq -e '.findings[]?|select(.edge_source?=="grep" and (.confidence//0)<0.3)' "$f" >/dev/null; then
      echo "Low-confidence grep-only finding in $f"
      low_conf=$((low_conf+1))
    fi
  fi
done
if [[ $low_conf -gt 0 ]]; then
  err "low-confidence grep-only findings ($low_conf); run joern/lsp to confirm or override"
  [[ -z "$OVERRIDE_REASON" ]] && exit 1 || warn "override applied: $OVERRIDE_REASON"
fi

if [[ $SKIP_REPORT -eq 0 ]]; then
  echo "[10] report"
  python "$ROOT/tools/scripts/generate_finding_report.py" "$REPO" "$STATE"/task_*_result.json --output "$STATE/finding_report.md" --source-label "$REPO" || true
else
  log "report skipped"; skips+=("report")
fi

# summary JSON (machine-readable for CI)
SUMMARY_JSON="$STATE/audit_summary.json"
python - "$STATE" "$RUN_ID" "$LABEL" "$SCOPE" "$HEAD_HASH" "$fail_count" "${quarantine[*]:-}" "${skips[*]:-}" <<'PY'
import json, sys, glob
state, run_id, label, scope, head_hash, fail = sys.argv[1:7]
quarantine = sys.argv[7].split() if len(sys.argv) > 7 and sys.argv[7] else []
skips = sys.argv[8].split() if len(sys.argv) > 8 and sys.argv[8] else []
unknown_cnt = 0
for path in glob.glob(f"{state}/task_*_result.json"):
    try:
        data = json.load(open(path))
        unknown_cnt += sum(1 for f in data.get("findings", []) if str(f.get("status","")).startswith("unknown"))
    except Exception:
        pass
import os
summary = {
    "run_id": run_id,
    "run_label": label,
    "snapshot_scope": scope,
    "repo_head": head_hash,
    "fail_count": int(fail),
    "quarantine": quarantine,
    "skips": skips,
    "unknown_count": unknown_cnt,
    "decompile_status": os.environ.get("DECOMP_STATUS_ENV",""),
}
json.dump(summary, open(f"{state}/audit_summary.json","w"), indent=2)
print(f"summary written: {state}/audit_summary.json")
PY

if [[ ${#quarantine[@]} -gt 0 ]]; then
  err "quarantined files: ${quarantine[*]}"
  echo "Quarantined (validation failed): ${quarantine[*]}"
  if [[ -z "$OVERRIDE_REASON" ]]; then exit 1; else warn "override applied: $OVERRIDE_REASON"; fi
fi

if [[ $fail_count -gt 0 ]]; then
  echo "Run completed with warnings/failures ($fail_count). See provenance_log."
  if [[ -z "$OVERRIDE_REASON" ]]; then exit 1; else warn "override applied: $OVERRIDE_REASON"; fi
fi

echo "run complete. RUN_ID=$RUN_ID"
