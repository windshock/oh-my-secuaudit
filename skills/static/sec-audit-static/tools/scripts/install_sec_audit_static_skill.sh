#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SRC_SKILL="${REPO_ROOT}/skills/sec-audit-static"
DEST_SKILL="${HOME}/.codex/skills/local/sec-audit-static"

if [ ! -d "${SRC_SKILL}" ]; then
  echo "Error: source skill not found at ${SRC_SKILL}" >&2
  exit 1
fi

mkdir -p "${DEST_SKILL}"

copy_item() {
  local src="$1"
  local dest="$2"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a "${src}" "${dest}"
  else
    cp -R "${src}" "${dest}"
  fi
}

# Copy core skill assets
copy_item "${SRC_SKILL}/SKILL.md" "${DEST_SKILL}/"
copy_item "${SRC_SKILL}/references" "${DEST_SKILL}/"

# Copy shared assets from playbook root
copy_item "${REPO_ROOT}/tools" "${DEST_SKILL}/"
copy_item "${REPO_ROOT}/schemas" "${DEST_SKILL}/"
copy_item "${REPO_ROOT}/skills/SEVERITY_CRITERIA_DETAIL.md" "${DEST_SKILL}/"
copy_item "${REPO_ROOT}/skills/REPORTING_SUMMARY_CONFIG.json" "${DEST_SKILL}/"
copy_item "${REPO_ROOT}/skills/REPORTING_SUMMARY_CONFIG.example.json" "${DEST_SKILL}/"
copy_item "${REPO_ROOT}/skills/USAGE_EXAMPLES.md" "${DEST_SKILL}/"

echo "Installed sec-audit-static skill to ${DEST_SKILL}"
echo "Example:"
echo "  ${DEST_SKILL}/tools/scripts/scan_api.py --repo <target> --output <state.json>"
