#!/usr/bin/env bash
# Fast lint to detect drift between plan and implementation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
FAIL=0

require_file() { [[ -f "$1" ]] || { echo "MISSING: $1"; FAIL=1; }; }
require_text() { local file=$1 text=$2; if ! grep -q "$text" "$file"; then echo "TEXT_MISSING: $text in $file"; FAIL=1; fi; }

# Required scripts
for f in tools/scripts/run_static_audit.sh tools/scripts/check_versions.sh tools/scripts/ensure_facets_and_state.py tools/scripts/derive_facets.py tools/scripts/check_unknowns.py tools/scripts/rank_candidates.py tools/scripts/high_risk_fuzz_gate.py tools/scripts/slice_context.py; do
  require_file "$ROOT/$f"
done

# SKILL helper sequence check
require_text "$ROOT/SKILL.md" "run_static_audit.sh"
require_text "$ROOT/SKILL.md" "derive_facets.py"
require_text "$ROOT/SKILL.md" "ensure_facets_and_state.py"
require_text "$ROOT/SKILL.md" "check_unknowns.py"

# versions.lock presence
require_file "$ROOT/versions.lock"

if [[ $FAIL -ne 0 ]]; then
  echo "lint failed"
  exit 1
fi
echo "lint OK"
