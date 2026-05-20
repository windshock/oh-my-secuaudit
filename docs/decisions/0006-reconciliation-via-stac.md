# ADR-0006: Finding reconciliation owned by security-testing-as-code

- Status: Proposed
- Date: 2026-05-20

## Context

[ADR-0004](0004-finding-id-namespace.md) establishes a single `FINDING-NNN` namespace across all finding-producing skills. [ADR-0001](0001-shared-finding-schema.md) enforces a common base across producer finding schemas (common-base enforcement, not byte-for-byte hash equality). [ADR-0002](0002-cluster-vs-finding.md) keeps clusters and findings as separate layers.

What none of these specify: **where canonical `FINDING-NNN` minting and cross-producer deduplication actually happen.** In practice multiple producers may detect the same underlying vulnerability — SAST on `handler.py:47`, DAST on `/foo?q=`, external on a dependency CVE. Each producer's task_output contains a candidate finding. Without a reconciliation step, the single-namespace promise of ADR-0004 cannot be enforced.

A second constraint is LLM context budget ([ADR-0003](0003-provenance-token-economy.md)). Producers and downstream skills are expected to execute under bounded context. Any reconciliation contract must allow harness-level partitioning without prescribing it.

[Issue #3](https://github.com/windshock/oh-my-secuaudit/issues/3) surfaced a downstream symptom of the missing reconciliation contract: the `security-testing-as-code` methodology template and the producer `finding_schema.json` diverged because the role of STAC in the finding lifecycle was never spelled out.

## Decision

**`security-testing-as-code` (STAC) owns finding reconciliation.** Producers emit per-task candidate findings. STAC ingests them, deduplicates, and mints canonical `FINDING-NNN`. The canonical store lives at `analysis/findings/<FINDING-NNN>.json` inside the assessment project tree that STAC already owns.

### Pipeline position

```
producers (sec-audit-static, sec-audit-dast,
           external-software-analysis,
           security-architecture-review)
   │  per-task candidate task_outputs
   ▼
STAC reconcile
   │  canonical FINDING-NNN
   ▼
analysis/findings/  (canonical store)
   │
   ▼
downstream consumers (SPR linkage, reporting roll-ups, ...)
```

### Requirements on the reconciliation step

The reconciliation step MUST be:

- **Partitionable**: the harness MAY execute reconciliation as a single agent, as multiple subagents partitioned along any axis (cluster_id, source skill, attack surface), or as a sequential pass. This ADR does not prescribe the partition strategy; the harness chooses based on its own context primitives (Claude Code `context: fork` / subagents, Codex subagent orchestration, etc.).
- **Deterministic**: given the same candidate inputs and the same algorithm version, the candidate → canonical mapping is the same. The set of canonical findings produced is independent of execution order.
- **Reproducible**: the canonical store carries enough audit-trail metadata to re-derive itself from the producer task_outputs and the reconcile algorithm version. The specific audit-trail fields (source candidate references, input hashes, algorithm version, target snapshot) are defined in ADR-0007.

### Reconciliation vs consolidation

These two operations are distinct and live in different skills:

- **Reconciliation (this ADR, STAC)**: dedup at the finding layer. One vuln = one `FINDING-NNN`. Pre-condition for everything downstream.
- **Consolidation (existing, SAR/SPR)**: rendering canonical findings grouped by remediation requirement (SPR) or attack scenario (architecture_handoff). Post-condition view.

### Producer task_output handling

Producer task_outputs become intermediate candidate artifacts. They are not the canonical store, and downstream skills that need a canonical view must consume the canonical store rather than per-task outputs. The producer `task_output_schema.json` contracts (ADR-0001) are not changed by this ADR.

## Out of scope (deferred)

This ADR establishes the owner and the abstract requirements only. The following are explicitly deferred:

- **Canonical finding schema shape, producer ID semantics (candidate vs canonical), provenance aggregation rules, `metadata.source_skill` cardinality, `cluster_id` cardinality, audit-trail field specifics** → **ADR-0007** (canonical finding schema).
- **Cross-cluster duplicate routing, cluster split/merge, security-architecture-review-originated finding flow, README End-to-End Relationship Map "Normalize" layer ownership, validator boundary across producer task_output / canonical per-finding / methodology template** → **ADR-0008** (cross-skill reconciliation contract).
- **Harness execution model** (sub-process partitioning strategy, ID range allocation, matching algorithm details, fuzzy match thresholds, human-gate UX) → implementation guidance, not ADR-level.

## Consequences

- The "no duplicate finding" promise of ADR-0004 has a named owner. The contract gap behind that promise can now be closed by ADR-0007 (schema) and ADR-0008 (cross-skill routing).
- Producers stay symmetric — none is promoted to reconciler.
- Harness-level execution detail stays out of the contract. Both Claude Code (`context: fork`, subagents) and Codex (explicit subagent orchestration) can implement the partitioning consistently with their primitives.
- Producer task_outputs are reframed as intermediate (candidate) artifacts. This is documentation framing, not a schema change to producer contracts.
- Issue #3 cannot be fully resolved by this ADR alone — it requires ADR-0007 to define the canonical schema and the realignment of `security-testing-as-code/templates/finding.json`. This ADR is a prerequisite.

## Open items (tracked separately)

- `docs/contracts/README.md` describes ADR-0001 as "hash-equal across the three producers". The validator actually enforces common-base, not byte-equality (see `scripts/validate_skills_repo.py`). That stale phrasing is a separate small docs fix, not part of this ADR.
- `security-testing-as-code/templates/finding.json` already drifts from ADR-0005 (status enum) and from any future canonical schema. Realignment lands with the ADR-0007 implementation PR.
