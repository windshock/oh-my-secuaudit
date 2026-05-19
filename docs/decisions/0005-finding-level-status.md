# ADR-0005: Add finding-level `status` enum

- Status: Accepted
- Date: 2026-05-19

## Context

`finding_schema.json` defines `task.status` at the top level (`completed | failed | partial`) — the state of the audit *task*, not of an individual finding inside it.

Per-finding lifecycle (was this triaged? confirmed? fixed? a false positive?) is missing from the schema. Real finding JSONs invent it freeform: `"status": "confirmed"`, `"status": "needs-manual-review"`, etc. SPRs reference findings via `linked_findings` and need to know when a finding has been fixed before the SPR can move to `done`.

Token cost of adding the field: roughly 3 tokens per finding (`"status":"confirmed"`). Acceptable given the workflow value (SPR closure tracking, false-positive accounting, fix-verification gates).

## Decision

Add an optional `status` field to each finding inside `finding_schema.json#/properties/findings/items`:

```json
"status": {
  "type": "string",
  "enum": [
    "confirmed",
    "needs-manual-review",
    "false-positive",
    "fixed",
    "deferred"
  ],
  "description": "Finding-level lifecycle state. Distinct from task.status."
}
```

The field is optional to preserve backward compatibility with existing finding stores that omit it. New audits should populate it.

### Value semantics

| Value | Meaning |
|---|---|
| `confirmed` | Evidence supports the claim. `provenance` should be one of source/runtime/binary-confirmed. |
| `needs-manual-review` | Candidate; not yet triaged. Typical for SAST sweep output before human review. |
| `false-positive` | Reviewed and determined not to be a vulnerability. Keep for triage accounting. |
| `fixed` | Code change verified to eliminate the vulnerability. Linked SPR can move toward `done`. |
| `deferred` | Acknowledged but not scheduled for fix (with rationale in `notes`). |

## Consequences

- SPR closure logic can read `linked_findings[*].status` to check if all are `fixed` before suggesting `SPR.status: done`.
- False-positive rate becomes computable per cluster — informs cluster bootstrapping decisions (see [ADR-0002](0002-cluster-vs-finding.md)).
- Drift values from existing finding JSONs (e.g., `"status": "confirmed"` already in use) are now schema-conforming after the schema update.
- ~3 tokens per finding cost. Within budget per [ADR-0003](0003-provenance-token-economy.md) since this is per-finding lifecycle, not per-token-sliced LLM context.
- Future state expansion (e.g., `claimed-fixed-verification-required` from shoppingtab review) requires an ADR + schema version bump.
