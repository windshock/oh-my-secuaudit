# ADR-0006: Finding reconciliation owned by security-testing-as-code

- Status: Proposed
- Date: 2026-05-20

## Context

[ADR-0004](0004-finding-id-namespace.md) establishes a single `FINDING-NNN` namespace across all producers (`sec-audit-static`, `sec-audit-dast`, `external-software-analysis`, `security-architecture-review`). [ADR-0001](0001-shared-finding-schema.md) enforces a common base across producer finding schemas. [ADR-0002](0002-cluster-vs-finding.md) keeps clusters and findings as separate layers.

What none of these specify: **where canonical `FINDING-NNN` minting and cross-producer deduplication actually happen.** In practice multiple producers may detect the same underlying vulnerability (SAST reads `handler.py:47`, DAST hits `/foo?q=`, external maps a known CVE on the dependency). Each producer's task_output contains a candidate finding. Without a reconciliation step, the single-namespace promise of ADR-0004 cannot be enforced — producer outputs would either collide on IDs or be allowed to duplicate the same vuln across producers.

A second constraint is LLM context budget ([ADR-0003](0003-provenance-token-economy.md)). Producers and downstream skills are expected to execute as bounded-context sub-processes. A reconciler that loads all producer outputs into one context window does not scale past a few clusters.

[Issue #3](https://github.com/windshock/oh-my-secuaudit/issues/3) surfaced a symptom of the missing reconciliation contract: the `security-testing-as-code` methodology template and the producer `finding_schema.json` diverged because the role of STAC in the finding lifecycle was never spelled out.

## Decision

**`security-testing-as-code` (STAC) owns finding reconciliation.** Producers emit per-task candidate findings. STAC ingests them, deduplicates against the canonical store, and mints canonical `FINDING-NNN`. The canonical store lives at `analysis/findings/<FINDING-NNN>.json` inside the assessment project tree that STAC already owns.

### Pipeline position

```
sec-cluster
   │  (cluster boundaries: C1, C2, ...)
   ▼
producers (per cluster, parallel allowed)
   │  task_output_<task_id>.json (candidates)
   ▼
STAC reconcile (per cluster, sub-process)
   │  canonical FINDING-NNN
   ▼
analysis/findings/  (canonical store)
   │
   ▼
security-architecture-review (SPR consumes canonical findings)
```

### Execution model: sub-process per cluster

Reconciliation runs as bounded sub-processes partitioned by `cluster_id`:

- STAC main process holds only orchestration metadata (cluster list, ID allocations).
- For each `cluster_id`, STAC spawns a sub-process that reads producer task_outputs filtered to that cluster.
- Each sub-process matches candidate findings within its cluster (matching keys: `sink_class`, `affected_file:line`, `affected_endpoint`, semantic similarity) and emits canonical findings.
- Findings without a `cluster_id` go to an off-cluster bucket with its own sub-process.

### ID broker

To avoid cross-sub-process contention:

- STAC main pre-allocates ID ranges per cluster (e.g., `C1 → FINDING-100..199`, `C2 → FINDING-200..299`, off-cluster → `FINDING-900..999`).
- Sub-processes mint canonical IDs from their own range. No central broker, no coordination round-trip.
- Range sizes are configurable; STAC's orchestration metadata records the allocation for reproducibility.

### Reconciliation vs consolidation (clarification)

- **Reconciliation (this ADR, STAC)**: dedup at the finding layer. One vuln = one `FINDING-NNN`. Pre-condition for everything downstream.
- **Consolidation (existing, SAR/SPR)**: rendering canonical findings grouped by remediation (SPR) or attack scenario (architecture_handoff). Post-condition view.

These are distinct operations and live in different skills.

### Producer task_output handling

- Producer task_outputs become "intermediate" artifacts stored under `artifacts/runtime/scans/<task_id>/task_output.json`.
- Producer-side ID fields (if any) are task-local and are remapped to canonical `FINDING-NNN` by STAC.
- Producer task_output remains validated by its own `task_output_schema.json` — this ADR does not change producer contracts.

### Canonical finding shape (resolves issue #3)

The canonical `analysis/findings/<FINDING-NNN>.json` validates against the producer `finding_schema.json` (per ADR-0001 common base) with optional fields added by STAC at reconcile time:

- `evidence_path` (optional): pointer to `artifacts/poc/<FINDING-NNN>/`
- `runtime_evidence_path` (optional): pointer to `artifacts/runtime/requests/finding-<NNN>.http`
- `metadata.source_skill` (per ADR-0004): list of producers that contributed candidates to this canonical finding.

The methodology template `security-testing-as-code/templates/finding.json` is realigned to this canonical shape: status enum unified to the [ADR-0005](0005-finding-level-status.md) set, container shape consistent with producer schema, methodology-only fields moved to optional extensions on the canonical schema.

`target_state` (commit/version/snapshot_date) lives at assessment level (`analysis/target_state.json` or README), not per finding.

## Consequences

- The "no duplicate finding" promise of ADR-0004 is now enforceable, not just declared.
- Producers stay symmetric — none is promoted to reconciler.
- Sub-process partitioning keeps each reconciliation execution bounded by cluster size (typically tens of candidates), compatible with the token-economy constraints of ADR-0003.
- Producer task_outputs become intermediate (candidate) artifacts; this is a documentation change, not a schema change.
- Issue #3's methodology/producer schema divergence resolves: one schema with optional STAC-filled extensions, not two parallel schemas.
- ADR-0001 hash-equality remains scoped to the three producers; STAC's canonical finding shape extends the common base with documented optional fields.
- Future: when sub-process architecture lands formally, the ID range allocation table and reconciliation matching rules will need their own implementation spec. This ADR establishes the model; the wire-level details follow.

## Open items

- Matching algorithm specifics (exact match keys, similarity threshold for fuzzy matches, human-in-the-loop UX) — defer to implementation spec.
- Whether SAR's architecture-review findings (which carry `metadata.source_skill: security-architecture-review` per ADR-0004) flow through STAC reconciliation or are minted directly. Likely STAC for consistency, but TBD.
