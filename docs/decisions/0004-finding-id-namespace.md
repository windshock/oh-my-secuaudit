# ADR-0004: Unify finding IDs under `FINDING-NNN` namespace

- Status: Accepted
- Date: 2026-05-19

## Context

Three finding-ID schemes co-exist across active audits:

- `VULN-001` — appears as the example in `finding_schema.json`.
- `FINDING-NNN` — used by recent SAST runs (e.g., gifticon audit).
- `F-ARCH-NNN` — used by architecture reviews (e.g., shoppingtab, ogog, fidosvr). SPRs reference these via `linked_findings`.

The architecture-review side and the SAST side both produce "findings" in the same sense (a vulnerability claim with evidence) but the namespaces never meet. SPRs only link to `F-ARCH-NNN`. `cluster_id` references and downstream joins have to know which namespace they are looking at.

## Decision

Unify all finding identifiers under `FINDING-NNN` going forward.

- New audits (regardless of producer skill) issue `FINDING-NNN` IDs.
- `finding_schema.json` example field updates from `VULN-001` to `FINDING-001`.
- Architecture-review findings carry `FINDING-NNN` IDs. The source of the finding is recorded in `metadata.source_skill` (`security-architecture-review` | `sec-audit-static` | `sec-audit-dast` | `external-software-analysis`).
- `SPR.linked_findings` continues to accept any string for one release cycle (backward compat).

### Legacy `F-ARCH-NNN`

Existing reviews use `F-ARCH-NNN` and we do not retroactively renumber them. Migration is tracked in `docs/migration/farch-to-finding.md` and executed lazily — when a review is re-run or amended, its findings are renumbered then.

### Why one namespace

A single namespace lets `cluster_id` and SPR `linked_findings` resolve any finding without disambiguation. It also lets the migration tracker keep one-to-one mapping rows.

## Consequences

- Single ID format simplifies downstream joins and reporting summaries.
- Producers tag the originating skill in metadata rather than in the ID prefix.
- `F-ARCH-NNN` remains valid in `SPR.linked_findings` validation for one cycle; second cycle the schema may tighten to `FINDING-NNN` only.
- Manual migration burden is bounded (a handful of reviews) and not blocking.
