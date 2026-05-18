#!/usr/bin/env python3
"""
Ensure unknown_* candidates/findings have attempted actions recorded.
Checks:
- unknown_reason must be present and in allowed taxonomy.
- flow or notes must include at least one attempt marker (edge/slice/runtime) when status is unknown_*.
Usage:
  python check_unknowns.py state/task_25_result.json
"""

import json
import sys
from pathlib import Path

ALLOWED_UNKNOWN = {
    "unknown_no_edges",
    "unknown_dynamic_dispatch",
    "unknown_context_budget",
    "unknown_needs_runtime",
    "unknown_tooling_error",
    "indeterminate_policy",
    "benign_unreachable",
}

ATTEMPT_MARKERS = ("edge:", "slice:", "runtime:", "fuzz:", "joern", "semgrep", "request_mapping")


def has_attempt(finding):
    flow = finding.get("flow") or []
    notes = finding.get("notes") or ""
    text = " ".join(flow) + " " + notes
    return any(marker in text.lower() for marker in ATTEMPT_MARKERS)


def main(files):
    bad = 0
    for file in files:
        path = Path(file)
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        for idx, f in enumerate(findings):
            if not isinstance(f, dict):
                continue
            reason = f.get("unknown_reason")
            status = f.get("status") or ""
            if status.startswith("unknown") or (reason and reason in ALLOWED_UNKNOWN):
                if reason not in ALLOWED_UNKNOWN:
                    print(f"{path}: finding[{idx}] invalid unknown_reason: {reason}")
                    bad += 1
                if not has_attempt(f):
                    print(f"{path}: finding[{idx}] unknown without attempt evidence")
                    bad += 1
    if bad:
        sys.exit(1)
    print("unknown checks passed.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1:])
