---
name: sec-audit-dast
description: DAST/ASM workflow for external asset discovery, probing, and scanning with SARIF output. Use for runtime/endpoint-based assessments and asset management scanning.
---

# Sec Audit DAST

## Overview
Run DAST/ASM pipelines (URL track and IP track) and produce SARIF outputs for findings. Use this when scanning live targets or external surfaces.

## Workflow
1. Read DAST references:
- `references/asm_sources.md` for canonical docs and process context.
- `references/asm_scripts.md` for the script entrypoints.
- `references/asm_csv.md` for CSV extraction from ASM outputs.
- `references/sarif_conversion.md` for CSV->SARIF conversion when needed.
- `references/severity_criteria.md` plus `references/severity_criteria_detail.md` for risk mapping.
- `references/reporting_summary.md` for the cross-skill summary index format.
2. Execute the appropriate track:
- URL Track: discovery -> probing -> scanners -> SARIF output.
- IP Track: IP list -> service/daemon detection -> SARIF output.
3. Normalize outputs to SARIF for reporting.
4. When producing JSON findings (or SARIF-to-JSON normalization), require:
- `provenance` with one of `binary-confirmed|source-confirmed|runtime-confirmed|not-confirmed`
- `impacted_flow` with one or more architecture flow IDs (`F1`, `F2`, ...)

## Reporting
- Primary output: SARIF (`.sarif`) per scan batch.
- Use severity mapping from `references/severity_criteria.md` and detailed criteria in `references/severity_criteria_detail.md`.
- Produce a common summary JSON using `schemas/reporting_summary_schema.json` in this skill directory.
- Use local scripts in this skill directory for conversion and summary generation.
- If task/finding JSON is emitted, validate against `schemas/task_output_schema.json` and `schemas/finding_schema.json`.

## Resources
### references/
- `references/asm_sources.md`
- `references/asm_scripts.md`
- `references/asm_csv.md`
- `references/sarif_conversion.md`
- `references/severity_criteria.md`
- `references/severity_criteria_detail.md`
- `references/reporting_summary.md`

### scripts/
- `scripts/asm_findings_to_csv.py`
- `scripts/sarif_from_csv.py`
- `scripts/generate_reporting_summary.py`

### schemas/
- `schemas/reporting_summary_schema.json`
- `schemas/task_output_schema.json`
- `schemas/finding_schema.json`
