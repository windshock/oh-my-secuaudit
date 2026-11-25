#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage:
  code_search.sh --repo <path> --query <regex> [--engine auto|rg|zoekt|zoekt-http] [--max <n>]

Behavior:
  - engine=auto: use remote Zoekt (zoekt-http) when ZOEKT_URL is set;
                 else local Zoekt when ZOEKT_ENABLED=1 and binaries exist;
                 else rg.
  - any Zoekt failure falls back to rg (non-blocking).

Remote Zoekt (zoekt-http) — query a shared zoekt-webserver instead of indexing locally:
  ZOEKT_URL     base URL of zoekt-webserver, e.g. http://localhost:6070
                (k8s: kubectl -n zoekt port-forward svc/zoekt 6070:6070)
  ZOEKT_REPO    repo filter (zoekt 'r:' regex). Unset => derive from basename(--repo);
                set empty ("") => search the whole index.
  Output is grep-style 'path:line:content' (same contract as rg).
  Note: the target repo must already be indexed on the server.
USAGE
}

REPO=""
QUERY=""
ENGINE="auto"
MAX=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="${2:-}"; shift 2 ;;
    --query)
      QUERY="${2:-}"; shift 2 ;;
    --engine)
      ENGINE="${2:-auto}"; shift 2 ;;
    --max)
      MAX="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2 ;;
  esac
done

if [[ -z "$REPO" || -z "$QUERY" ]]; then
  usage
  exit 2
fi

if [[ ! -d "$REPO" ]]; then
  echo "repo not found: $REPO" >&2
  exit 2
fi

HAS_ZOEKT=0
if command -v zoekt >/dev/null 2>&1 && command -v zoekt-index >/dev/null 2>&1; then
  HAS_ZOEKT=1
fi
REBUILD=${ZOEKT_REBUILD:-none}  # none|auto|force

select_engine() {
  if [[ "$ENGINE" == "rg" ]]; then
    echo "rg"
    return
  fi
  if [[ "$ENGINE" == "zoekt-http" ]]; then
    echo "zoekt-http"
    return
  fi
  if [[ "$ENGINE" == "zoekt" ]]; then
    echo "zoekt"
    return
  fi

  # auto: remote server first (no local indexing / disk), then local zoekt, then rg.
  if [[ -n "${ZOEKT_URL:-}" ]]; then
    echo "zoekt-http"
  elif [[ "${ZOEKT_ENABLED:-0}" == "1" && "$HAS_ZOEKT" == "1" ]]; then
    echo "zoekt"
  else
    echo "rg"
  fi
}

run_rg() {
  local args=(--line-number --no-heading --color=never -e "$QUERY" "$REPO")
  if [[ -n "$MAX" ]]; then
    rg "${args[@]}" | head -n "$MAX"
  else
    rg "${args[@]}"
  fi
}

run_zoekt() {
  if [[ "$HAS_ZOEKT" != "1" ]]; then
    return 1
  fi

  local index_root="${ZOEKT_INDEX_ROOT:-$HOME/.cache/zoekt}"
  mkdir -p "$index_root"

  local repo_key
  repo_key=$(printf '%s' "$REPO" | shasum | awk '{print $1}')
  local index_dir="$index_root/$repo_key"
  mkdir -p "$index_dir"

  if [[ "$REBUILD" == "force" ]]; then
    rm -rf "$index_dir" && mkdir -p "$index_dir"
  fi

  if [[ "$REBUILD" == "auto" && -n "${SNAPSHOT_HASH:-}" && -f "$index_dir/.hash" ]]; then
    prev=$(cat "$index_dir/.hash")
    if [[ "$prev" != "$SNAPSHOT_HASH" ]]; then
      rm -rf "$index_dir" && mkdir -p "$index_dir"
    fi
  fi

  if [[ -z "$(ls -A "$index_dir" 2>/dev/null || true)" ]]; then
    zoekt-index -index "$index_dir" "$REPO" >/dev/null 2>&1 || return 1
    [[ -n "${SNAPSHOT_HASH:-}" ]] && echo "$SNAPSHOT_HASH" > "$index_dir/.hash"
  fi

  # Zoekt output format can vary by build; keep passthrough and fallback on failure.
  if [[ -n "$MAX" ]]; then
    zoekt -index_dir "$index_dir" "$QUERY" 2>/dev/null | head -n "$MAX"
  else
    zoekt -index_dir "$index_dir" "$QUERY" 2>/dev/null
  fi
}

# Query a remote zoekt-webserver over HTTP and emit grep-style 'path:line:content'.
# Returns non-zero on any problem so the caller can fall back to rg.
run_zoekt_http() {
  [[ -n "${ZOEKT_URL:-}" ]] || return 1
  command -v curl >/dev/null 2>&1 || return 1
  command -v python3 >/dev/null 2>&1 || return 1

  # Repo scoping: unset ZOEKT_REPO => derive from basename(--repo); empty => whole index.
  local repo_filter q num
  repo_filter="${ZOEKT_REPO-__AUTO__}"
  if [[ "$repo_filter" == "__AUTO__" ]]; then
    repo_filter="$(basename "$REPO")"
  fi
  q="$QUERY"
  if [[ -n "$repo_filter" ]]; then
    q="r:${repo_filter} ${QUERY}"
  fi
  num="${MAX:-200}"

  local body
  body=$(curl -sS --max-time 25 --get \
          --data-urlencode "q=${q}" \
          --data-urlencode "format=json" \
          --data-urlencode "num=${num}" \
          "${ZOEKT_URL%/}/search" 2>/dev/null) || return 1
  [[ -n "$body" ]] || return 1

  printf '%s' "$body" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
r = d.get("result", {})
fms = r.get("FileMatches") or []
emitted = 0
for f in fms:
    fn = f.get("FileName", "")
    for m in (f.get("Matches") or []):
        ln = m.get("LineNum", "")
        frags = m.get("Fragments") or []
        content = "".join((fr.get("Pre","") + fr.get("Match","") + fr.get("Post","")) for fr in frags)
        sys.stdout.write("%s:%s:%s\n" % (fn, ln, content))
        emitted += 1
sys.exit(0 if emitted else 1)
' || return 1
}

E=$(select_engine)
case "$E" in
  zoekt-http)
    run_zoekt_http || run_rg ;;
  zoekt)
    run_zoekt || run_rg ;;
  *)
    run_rg ;;
esac
