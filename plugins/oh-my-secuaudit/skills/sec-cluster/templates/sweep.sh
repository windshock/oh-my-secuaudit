#!/usr/bin/env bash
# Run semgrep cluster rules against target modules.
# Usage:
#   ./sweep.sh            # all modules, all rules, human output
#   ./sweep.sh --json     # JSON output (machine-readable)
#   ./sweep.sh <module>   # single module
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/semgrep-rules"

# --- ADAPT: Set REPO_ROOT to target repository root ---
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

# --- ADAPT: List target modules (relative to REPO_ROOT) ---
MODULES=(
  # "src/main/java/com/example/api"
  # "modules/auth-service"
  # "modules/payment-service"
)

if [[ ${#MODULES[@]} -eq 0 ]]; then
  echo "ERROR: No modules configured. Edit MODULES array in this script." >&2
  exit 1
fi

# Collect all rule files
RULES=()
for f in "$RULES_DIR"/*.yaml "$RULES_DIR"/*.yml; do
  [[ -f "$f" ]] && RULES+=("$f")
done

if [[ ${#RULES[@]} -eq 0 ]]; then
  echo "ERROR: No rule files found in $RULES_DIR" >&2
  exit 1
fi

JSON_FLAG=""
TARGETS=()
for arg in "$@"; do
  case "$arg" in
    --json) JSON_FLAG="-json" ;;
    *) TARGETS+=("$arg") ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("${MODULES[@]}")
fi

OUT_DIR="$RULES_DIR/results"
mkdir -p "$OUT_DIR"

for module in "${TARGETS[@]}"; do
  module_path="$REPO_ROOT/$module"
  if [[ ! -d "$module_path" ]]; then
    echo "skip: $module (not found)" >&2
    continue
  fi
  echo "=== $module ==="
  for rule in "${RULES[@]}"; do
    echo "  rule: $(basename "$rule")"
    # Filter build artifacts and test sources
    semgrep -l java --config "$rule" $JSON_FLAG "$module_path" 2>/dev/null \
      | grep -v "/target/" \
      | grep -v "/build/" \
      | grep -v "/src/test/" \
      || true
  done
done
