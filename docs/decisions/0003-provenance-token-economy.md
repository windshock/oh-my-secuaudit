# ADR-0003: `provenance` is a token-economy compression, not a method/strength split

- Status: Accepted
- Date: 2026-05-19

## Context

`finding_schema.json` defines `provenance` as a 4-value closed enum:

```
binary-confirmed | source-confirmed | runtime-confirmed | not-confirmed
```

Real-world finding JSONs have drifted away from this. Observed values in active use include `semgrep-confirmed`, `static-analysis (grep enumeration; Joern fallback)`, and similar tool-named strings that fail the schema.

The natural-looking fix is to split the field — `discovery_method` (open enum: how was it found?) plus `confirmation` (closed enum: how strong is the evidence?). That respects taxonomy but doubles the token cost per finding.

`sec-audit-static-workflow-improvement-plan-v2.0.md` states the design constraint explicitly:

> only evidence-backed minimal sliced context should reach LLM steps.
> Keep strict token/line/function budgets for reportable context packs.

The workflow processes hundreds of findings per run through LLM phases. The compactness of `provenance` is not a taxonomy oversight; it is a context-budget contract. The 4 values fuse "how the evidence was obtained" with "how strong the conclusion is" into a single token-sized signal.

The same constraint motivates `sec-cluster`: code-graph completeness (e.g., Joern CPG) is unreliable in practice, so the workflow leans on `(Endpoint, Sink)` feature compression instead of full dataflow expansion. `provenance` and `cluster` are siblings in the same compression strategy.

## Decision

`provenance` stays at 4 values. The enum is closed and changes require an ADR plus schema version bump.

- `binary-confirmed` — confirmed via binary/decompiled analysis.
- `source-confirmed` — confirmed via source-code reading (manual or tool-assisted with manual verification).
- `runtime-confirmed` — confirmed via runtime test (PoC, dynamic scanner, fuzz hit).
- `not-confirmed` — claim is unproven; no strong evidence yet.

Tool names (semgrep, joern, gitleaks, etc.) and verbose evidence descriptions belong in `notes`, `evidence`, or metadata — not in `provenance`.

### Drift mapping

Existing finding JSONs with non-conforming `provenance` values are mapped during migration:

| Drift value | Maps to | Condition |
|---|---|---|
| `semgrep-confirmed` (no manual verification) | `not-confirmed` | Tool alone, no human/runtime confirmation |
| `semgrep-confirmed` (manual review done) | `source-confirmed` | After human read the code |
| `static-analysis (grep enumeration; Joern fallback)` | `not-confirmed` | Population enumeration without per-instance verification |
| `code-confirmed` | `source-confirmed` | Equivalent in intent |
| `partially-confirmed` | `not-confirmed` with `status: needs-manual-review` | Strength is below confirmed threshold |

## Consequences

- LLM context budget for findings stays compact.
- Tool-specific or method-specific detail moves to `notes`/metadata, kept out of the strict critical path.
- New evidence methods (e.g., fuzz-confirmed, dast-confirmed) require an ADR — they are not added casually.
- Drift cleanup is a migration task, not a schema relaxation.
- Companion ADRs ([ADR-0001](0001-shared-finding-schema.md), [ADR-0002](0002-cluster-vs-finding.md)) protect the same compression contract on adjacent fields.
