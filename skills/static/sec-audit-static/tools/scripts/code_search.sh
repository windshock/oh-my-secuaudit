#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage:
  code_search.sh --repo <path> --query <regex> [--engine auto|rg|zoekt] [--max <n>]

Behavior:
  - engine=auto: use Zoekt only when ZOEKT_ENABLED=1 and binaries exist, else rg
  - if Zoekt index/query fails, fallback to rg
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
  if [[ "$ENGINE" == "zoekt" ]]; then
    echo "zoekt"
    return
  fi

  if [[ "${ZOEKT_ENABLED:-0}" == "1" && "$HAS_ZOEKT" == "1" ]]; then
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

  if [[ "$REBUILD" == "auto" && -n "$SNAPSHOT_HASH" && -f "$index_dir/.hash" ]]; then
    prev=$(cat "$index_dir/.hash")
    if [[ "$prev" != "$SNAPSHOT_HASH" ]]; then
      rm -rf "$index_dir" && mkdir -p "$index_dir"
    fi
  fi

  if [[ -z "$(ls -A "$index_dir" 2>/dev/null || true)" ]]; then
    zoekt-index -index "$index_dir" "$REPO" >/dev/null 2>&1 || return 1
    [[ -n "$SNAPSHOT_HASH" ]] && echo "$SNAPSHOT_HASH" > "$index_dir/.hash"
  fi

  # Zoekt output format can vary by build; keep passthrough and fallback on failure.
  if [[ -n "$MAX" ]]; then
    zoekt -index_dir "$index_dir" "$QUERY" 2>/dev/null | head -n "$MAX"
  else
    zoekt -index_dir "$index_dir" "$QUERY" 2>/dev/null
  fi
}

E=$(select_engine)
if [[ "$E" == "zoekt" ]]; then
  if ! run_zoekt; then
    run_rg
  fi
else
  run_rg
fi
