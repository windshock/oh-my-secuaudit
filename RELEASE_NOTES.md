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

### Changed
- `README.md` now includes a developer workflow section that connects local checks, CI checks, and release guidance.
- `ROADMAP.md` realigned to a Level 2 plan (examples-first, `--with-examples` schema validation, minimal CI expansion, explicit out-of-scope).
- `README.md` End-to-End Relationship Map redesigned into 4 layers (producer -> normalize -> synthesis -> lifecycle) with explicit line semantics (required/optional/continuous).

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
