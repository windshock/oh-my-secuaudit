# ADR-0002: Cluster and finding are separate layers

- Status: Accepted
- Date: 2026-05-19

## Context

`sec-cluster` produces dataflow-based clusters — groupings of `(Endpoint, Sink)` pairs that share a review strategy. Clusters are *review hypotheses*, not vulnerability claims. The skill outputs markdown documents (`CLUSTERS.md`, `REVIEW_CHECKLIST.md`) plus adapted semgrep rules.

`sec-audit-static`, `sec-audit-dast`, and `external-software-analysis` produce findings — *review conclusions* under `schemas/finding_schema.json`. A finding is a confirmed (or partially-confirmed) vulnerability at one or more locations.

Real-world drift: at least one project's finding store mixed the two. An entry like "309 endpoints lack authentication, needs cluster sampling" was filed as a finding even though no individual vulnerability claim had been made yet. That conflates the two layers.

The blog post [How I Turned 228 Endpoints into 5 Clusters](https://windshock.github.io/en/post/2026-04-15-security-code-clustering/) makes the layering explicit:

> A cluster does not guarantee identical results. A cluster provides the possibility of applying the same review strategy.

The cluster's lifecycle (Stage 1 → Stage 2 → Stage 3 based on intra-cluster consistency) is also distinct from any individual finding's lifecycle.

## Decision

Treat cluster and finding as separate artifact layers:

- **Cluster** (sec-cluster):
  - Primary output: markdown per existing templates (`CLUSTERS.md.tmpl`, `REVIEW_CHECKLIST.md.tmpl`).
  - Machine-readable sidecar: new `cluster_metadata_schema.json` in `sec-cluster/schemas/`. Captures cluster ID, (endpoint,sink) feature table, bootstrapping stage, consistency rate, sample verdicts, re-verification triggers.
  - Lifecycle: `defined → stage-1 → stage-2 → stage-3 → re-verify-required`.

- **Finding** (sec-audit-static/dast/external-software-analysis):
  - Primary output: JSON per `finding_schema.json`.
  - Optional link back to cluster: new optional `cluster_id` field (introduced in this PR).
  - Lifecycle: per [ADR-0005](0005-finding-level-status.md) `confirmed | needs-manual-review | false-positive | fixed | deferred`.

## Consequences

- Existing "cluster-as-finding" entries (e.g., the 309-endpoints case) are misfiled. Migration to CLUSTERS.md tracked in `docs/migration/farch-to-finding.md`.
- `cluster_id` is optional on finding so existing producers don't break.
- Bootstrapping stages live in cluster metadata, not duplicated per finding.
- Downstream skills can resolve "show me everything in cluster C1" via the finding's `cluster_id` join key.
