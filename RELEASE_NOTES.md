# Release Notes

## Unreleased

### Added
- Repository contract validation script:
  - `scripts/validate_skills_repo.py`
- Local task runner:
  - `justfile` (`check`, `ci-check`, `status`)
- GitHub CI workflow:
  - `.github/workflows/ci.yml` (runs validation on `push`/`pull_request`)
- Release operating guide:
  - `.github/RELEASE_GUIDE.md`
- New skill: `skills/static/sec-cluster` — dataflow-based security code clustering (v4 strategy):
  - `SKILL.md` with full 6-phase workflow
  - `references/clustering_strategy_v4.md` — strategy reference document
  - `templates/semgrep-rules/` — 4 category rule templates (C2 shared-secret, C3 hostname-bypass, C4 sensitive-logging, C5 unsafe-deserialization)
  - `templates/sweep.sh` — module sweep runner
  - `templates/auth_enum.sh` — C1 auth mechanism enumeration helper
  - `templates/CLUSTERS.md.tmpl` — cluster document template
  - `templates/REVIEW_CHECKLIST.md.tmpl` — bootstrapping review checklist template
- New skill: `skills/methodology/security-testing-as-code` — assessment-as-executable-project workflow:
  - `SKILL.md` with project structure, PoC standards, handoff plan workflow
  - `references/project_structure.md` — directory layout reference
  - `references/poc_standards.md` — PoC quality and safety guidelines
  - `templates/assessment/` — starter project template (copy to begin new assessment)
  - `templates/finding.json` — finding record template
  - `templates/poc-readme.md` — PoC README template
  - `templates/handoff-plan.md` — handoff plan template

### Changed
- `README.md` now includes a developer workflow section that connects local checks, CI checks, and release guidance.
- `README.md` updated with Claude Code setup guide alongside existing Codex instructions.
- `README.md` capability matrix expanded with `sec-cluster` and `security-testing-as-code` entries.
- `README.md` End-to-End Relationship Map redesigned into 4 layers (producer -> normalize -> synthesis -> lifecycle) with explicit line semantics (required/optional/continuous).
- `README.md` Relationship Map now includes `sec-cluster` (Layer 1) and `security-testing-as-code` (Layer M: Methodology) nodes.
- `README.md` Relationship Map now includes manual external threat research as a first-class context input and feedback target.
- `scripts/validate_skills_repo.py` updated to validate new skill directories.
- Removed case-derived vulnerability intake example set from docs and references to keep guidance fully generic.

## 2026-03-03 - v0.4.0

### Added
- Closed-loop producer/architecture model documentation in `README.md`.
- Architecture-to-product requirement lifecycle in `security-architecture-review`:
  - `SPR-*` generation rules
  - lifecycle delta tracking (`added|updated|closed|deferred|accepted-risk`)
  - persistent backlog expectations
- New architecture review assets:
  - `skills/architect/security-architecture-review/references/security_product_requirements_template.md`
  - `skills/architect/security-architecture-review/schemas/security_product_requirement_schema.json`
- Self-contained runtime/external schemas and scripts:
  - `skills/runtime/sec-audit-dast/schemas/*`
  - `skills/runtime/sec-audit-dast/scripts/*`
  - `skills/external/external-software-analysis/schemas/*`
  - `skills/external/external-software-analysis/scripts/*`

### Changed
- `security-architecture-review` rules strengthened:
  - boundary representation standardized to Mermaid `subgraph` zones
  - attack flow organization standardized to scenario-centric `AS-*` grouping
  - external runtime-hop components must be explicit DFD nodes/edges
- README expanded from simple mapping to actionable orchestration:
  - capability matrix
  - handoff contract
  - quality gates
  - color-coded relationship map

### Removed
- `skills/architect/security-architecture-recon` (consolidated into review-centric workflow).

### Notes
- This release focuses on synthesis quality, traceability, and continuous requirement management instead of one-off reporting.

## 2026-03-03 - v0.3.0

### Added
- Initial static/runtime/external/architect skill set in this repository.

### Changed
- Repository hygiene updates and generated artifact cleanup.
