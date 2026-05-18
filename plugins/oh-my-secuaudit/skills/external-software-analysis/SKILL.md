---
name: external-software-analysis
description: External software analysis workflows for binaries/packages (decompilation, reverse engineering, static analysis, fuzzing, and evidence collection). Use when analyzing third-party software without source access.
---

# External Software Analysis

## Overview
Guide external software analysis from decompilation to vulnerability discovery and evidence collection. Output is a structured Markdown report.

## Workflow
1. Read `references/external_sources.md` for local canonical references.
2. Apply the discovery process (decompile -> static scan -> flow tracing -> evidence).
3. Produce a Markdown report following the reference report structure.
4. When summarizing, map severity using `references/severity_criteria.md` and `references/severity_criteria_detail.md`.
5. If JSON findings are emitted, they must conform to `schemas/finding_schema.json` and include:
   - `provenance` (one of `binary-confirmed|source-confirmed|runtime-confirmed|not-confirmed`)
   - `impacted_flow` (one or more flow IDs such as `F1`, `F2`)

## Skill Interop: security-architecture-review
- Use this handoff when binary/package findings affect service trust boundaries, data flows, or authz decisions.
- Produce a compact handoff section (or separate markdown) with:
  - External component name/version/artifact path
  - Integration points (caller/callee, endpoint/function, file evidence)
  - Data-in/data-out and sensitive fields touched
  - Security control assumptions at the boundary (TLS, signature, token validation, pinning)
  - Finding-to-flow mapping (`finding_id -> impacted flow/boundary`)
  - Evidence provenance tag per claim: `binary-confirmed`, `source-confirmed`, `runtime-confirmed`, `not-confirmed`
- When source code is available for the integrating service, explicitly cross-check and upgrade provenance tags where possible.
- Reference template: `references/architecture_handoff.md`.

## Reporting
- Primary output: Markdown report (example reference provided).
- Use severity mapping from `references/severity_criteria.md` and detailed criteria in `references/severity_criteria_detail.md`.
- Produce a common summary JSON using `schemas/reporting_summary_schema.json` in this skill directory.
- When task-level JSON is required, use `schemas/task_output_schema.json`.
- Use `scripts/generate_reporting_summary.py` in this skill directory to build JSON output.
- For cross-skill usage, also emit a handoff markdown file (default: `./external-analysis-architecture-handoff.md`) using `references/architecture_handoff.md`.

## Resources
### references/
- `references/external_sources.md`
- `references/external_report_template.md`
- `references/discovery_process.md`
- `references/severity_criteria.md`
- `references/severity_criteria_detail.md`
- `references/reporting_summary.md`
- `references/architecture_handoff.md`

### schemas/
- `schemas/reporting_summary_schema.json`
- `schemas/task_output_schema.json`
- `schemas/finding_schema.json`

### scripts/
- `scripts/generate_reporting_summary.py`
