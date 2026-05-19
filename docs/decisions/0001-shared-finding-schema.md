# ADR-0001: Enforce common base across producer finding schemas

- Status: Accepted
- Date: 2026-05-19

## Context

Three producer skills emit findings: `sec-audit-static`, `sec-audit-dast`, `external-software-analysis`. Each carries its own copy of `schemas/finding_schema.json` and `schemas/task_output_schema.json`. `validate_skills_repo.py` currently enforces SHA256 equality only on `reporting_summary_schema.json`.

Inspection on 2026-05-19 shows the finding/task_output schemas are **not currently hash-equal**, and the drift is legitimate:

- `sec-audit-static` additionally requires `request_mapping`, `flow`, `layer`, `boundary`, `sink_class` per the workflow plan v2.0 facet-tag rule, and `state_store_run_id`, `snapshot_scope` in metadata for the State Store contract.
- `sec-audit-dast` and `external-software-analysis` do not need these SAST-specific fields (DAST has no controller layer; binary analysis has no `request_mapping`).

Naive hash-equal enforcement would falsely flag this divergence as drift.

But the *common* shape — the subset that downstream consumers (`sec-cluster`, SPR linkage, security-testing-as-code) actually rely on — should be identical. If producer A says `severity` allows `"Severe"` while producer B says `["Critical", "High", "Medium", "Low", "Info"]`, downstream aggregation breaks silently.

## Decision

Define a **common finding base** that all three producer schemas must declare, and enforce that base in CI. Producer-specific extensions are permitted on top.

### Common finding base (must be present in all three `finding_schema.json#/properties/findings/items`)

- Required fields: `id`, `title`, `severity`, `category`, `description`, `provenance`, `impacted_flow`
- `severity` enum: exactly `["Critical", "High", "Medium", "Low", "Info"]` (closed)
- `provenance` enum: exactly `["binary-confirmed", "source-confirmed", "runtime-confirmed", "not-confirmed"]` (closed, see [ADR-0003](0003-provenance-token-economy.md))
- `impacted_flow`: array of strings, `minItems: 1`
- Optional standardized: `cwe_id` (pattern `CWE-NNN`), `owasp_category`, `affected_endpoint`, `affected_file`, `evidence`, `recommendation`, `notes`
- Newly added in this PR: optional `cluster_id` (links to cluster metadata per [ADR-0002](0002-cluster-vs-finding.md)), optional `status` enum (per [ADR-0005](0005-finding-level-status.md))

### Reporting summary

`reporting_summary_schema.json` remains hash-equal across the three producers (pre-existing constraint). It has no producer-specific concerns.

### Task output

`task_output_schema.json` does *not* need to be hash-equal. It wraps `findings[]` and producer-specific metadata. The validator instead checks the common required keys: `task_id`, `status`, `findings`, `metadata`, and metadata required fields `source_repo_url`, `source_repo_path`, `source_modules`.

### Validation mechanism

`scripts/validate_skills_repo.py` is extended to:

1. For each of the three producer `finding_schema.json` files, parse and assert:
   - `findings.items.required` contains the common base required fields.
   - `findings.items.properties.severity.enum` equals the common severity set.
   - `findings.items.properties.provenance.enum` equals the common provenance set.
   - If `status` is declared, its enum matches the [ADR-0005](0005-finding-level-status.md) set.
2. For each of the three producer `task_output_schema.json` files, parse and assert the common top-level required keys exist.
3. `reporting_summary_schema.json` SHA256 hash-equal check (unchanged).

A small JSON-Schema-parsing validator suffices — no jsonschema library required, just `json.loads` + dict checks (zero new dependencies, matches the existing script style).

## Consequences

- Producer-specific extensions are explicit and tracked. `sec-audit-static`'s SAST extras are documented divergence, not drift.
- Adding a new common required field requires updating all three schemas in one PR (CI fails otherwise).
- Adding a producer-specific field requires only that producer's schema.
- New optional common fields (this PR adds `cluster_id`, `status`) are added to all three identically.
- Future refactor to a single shared base + `$ref` extensions is open; this ADR does not block it.
