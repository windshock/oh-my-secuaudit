#!/usr/bin/env bash
# CI gate for sec-audit-static outputs.
set -euo pipefail

SUMMARY=${1:-appif5/state/audit_summary.json}

if [[ ! -f "$SUMMARY" ]]; then
  echo "summary not found: $SUMMARY"
  exit 1
fi

fail_count=$(jq -r '.fail_count' "$SUMMARY")
quarantine=$(jq -r '.quarantine|length' "$SUMMARY")
unknown=$(jq -r '.unknown_count' "$SUMMARY")
skips=$(jq -r '.skips|join(",")' "$SUMMARY")
decomp=$(jq -r '.decompile_status // ""' "$SUMMARY")

echo "fail_count=$fail_count"
echo "quarantine=$quarantine"
echo "unknown_count=$unknown"
echo "skips=$skips"
echo "decompile_status=$decomp"

if [[ "$fail_count" != "0" ]]; then
  echo "CI gate: fail_count > 0"
  exit 1
fi
if [[ "$quarantine" != "0" ]]; then
  echo "CI gate: quarantined files present"
  exit 1
fi
# enforce decompile parity unless waived/override
if [[ "$decomp" == "skipped" ]]; then
  echo "CI gate: decompile pass skipped without waiver"
  exit 1
fi

echo "CI gate passed."
