# Contracts

This directory documents the output contracts (JSON Schemas and structural markdown templates) that hook the oh-my-secuaudit skills together. The contracts themselves live next to the skills that own them; this README is the index.

The contracts exist because the workflow is **LLM-driven** and runs under strict context-budget constraints. Drift between producer output and consumer expectation is silent and expensive. See [ADR-0003](../decisions/0003-provenance-token-economy.md) for the design constraint.

## Pipeline

```
            sec-cluster
                │  (review strategy)
                ▼
        CLUSTERS.md  +  cluster_metadata.json
                │
                ▼
   sec-audit-static / sec-audit-dast / external-software-analysis
                │  (review conclusions)
                ▼
        finding_schema.json  +  task_output_schema.json
                │
                ▼ (reporting roll-up)
        reporting_summary_schema.json
                │
                ▼
   security-architecture-review
                │  (handoff: DFD, attack surface, scenarios)
                ▼
        architecture_handoff_schema.json
                │
                ▼  (remediation requirements)
        security_product_requirement_schema.json  (SPR)
```

Each arrow is a contract boundary that the CI validator (`scripts/validate_skills_repo.py`) enforces.

## Contracts

### Finding (existing, strict)

- **Producer**: `sec-audit-static`, `sec-audit-dast`, `external-software-analysis`
- **Schema**: `plugins/oh-my-secuaudit/skills/<skill>/schemas/finding_schema.json`
- **Common-base enforcement across the three producers** ([ADR-0001](../decisions/0001-shared-finding-schema.md)) — producer-specific extensions are permitted on top; the validator checks the common required fields and closed enums, not byte equality.
- Per-finding `provenance` is a closed 4-value enum — token-economy compression ([ADR-0003](../decisions/0003-provenance-token-economy.md))
- Per-finding `status` lifecycle: `confirmed | needs-manual-review | false-positive | fixed | deferred` ([ADR-0005](../decisions/0005-finding-level-status.md))
- Per-finding `cluster_id` optional, links to cluster_metadata ([ADR-0002](../decisions/0002-cluster-vs-finding.md))
- ID namespace: `FINDING-NNN` ([ADR-0004](../decisions/0004-finding-id-namespace.md))

### Task output (existing, strict)

- **Producer**: same three
- **Schema**: `plugins/oh-my-secuaudit/skills/<skill>/schemas/task_output_schema.json`
- **Common required keys across the three producers** ([ADR-0001](../decisions/0001-shared-finding-schema.md)) — the validator checks top-level required keys (`task_id`, `status`, `findings`, `metadata`) and metadata required fields (`source_repo_url`, `source_repo_path`, `source_modules`). Not byte-equal; producer-specific metadata is permitted.
- Wraps `findings[]` with task-level metadata (`source_repo_url`, `state_store_run_id`, `snapshot_scope`).

### Reporting summary (existing, strict)

- **Producer**: same three
- **Schema**: `plugins/oh-my-secuaudit/skills/<skill>/schemas/reporting_summary_schema.json`
- **Hash-equal across the three producers** (already enforced — pre-existing)
- Roll-up across audits, used for cross-skill summary index.

### Cluster metadata (new in this PR)

- **Producer**: `sec-cluster`
- **Schema**: `plugins/oh-my-secuaudit/skills/sec-cluster/schemas/cluster_metadata_schema.json`
- Machine-readable sidecar to the markdown templates (`CLUSTERS.md.tmpl`, `REVIEW_CHECKLIST.md.tmpl`).
- Captures (Endpoint, Sink) feature table, bootstrapping stage, intra-cluster consistency, sample verdicts.

### Architecture handoff (new in this PR)

- **Producer**: `security-architecture-review`
- **Schema**: `plugins/oh-my-secuaudit/skills/security-architecture-review/schemas/architecture_handoff_schema.json`
- Structural metadata for the markdown review (Flow IDs, Boundary IDs, Attack Scenario IDs, risk-tracking table rows).
- Markdown body remains free-form prose; structured tables/lists must match the schema.

### Security Product Requirement / SPR (existing, strict)

- **Producer**: `security-architecture-review`
- **Schema**: `plugins/oh-my-secuaudit/skills/security-architecture-review/schemas/security_product_requirement_schema.json`
- **Template**: `references/security_product_requirements_template.md`
- Groups findings by remediation requirement; tracks lifecycle (`draft | planned | in_progress | blocked | done | deferred | accepted-risk`).

## Evolution policy

| Field | Policy |
|---|---|
| `provenance` (finding) | Closed enum, ADR-only additions, version bump |
| `severity` (finding) | Closed enum aligned to CVSS bands, ADR-only additions |
| `status` (finding) | Closed enum, ADR-only additions |
| `status` (SPR) | Closed enum + `x-` extension allowed for project-specific lifecycle states |
| `layer`, `boundary`, `sink_class` | Closed enum + `unknown_*` fallback |
| `category` (finding) | Open string, but tooling may converge toward a taxonomy later |
| `tags`, `notes` | Free-form |

Adding any required field is breaking and requires:
1. ADR in `docs/decisions/`
2. Migration plan in `docs/migration/` if existing data needs change
3. Coordinated update across all shared-schema copies (hash-equal for `reporting_summary_schema.json`; common-base for `finding_schema.json`; common required keys for `task_output_schema.json`)

## Migration

Active migrations live under `docs/migration/`. The current one is `farch-to-finding.md` — moving legacy `F-ARCH-NNN` IDs to the unified `FINDING-NNN` namespace.

## Why this exists

Treating each skill as an isolated tool would be acceptable if the workflow were human-driven. It is not — LLM agents read producer output as input. Schema drift becomes silent prompt drift: agents quietly start to misread fields, miss required values, or generate incompatible output. The contracts here are the ABI between LLM-driven phases.

Related: `references/security_product_requirements_template.md`, the blog post [How I Turned 228 Endpoints into 5 Clusters](https://windshock.github.io/en/post/2026-04-15-security-code-clustering/), and `sec-audit-static-workflow-improvement-plan-v2.0.md`.
