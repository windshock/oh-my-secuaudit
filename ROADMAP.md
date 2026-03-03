# Roadmap

## Direction

Build a repeatable security workflow where producer skills and architecture review operate as a closed loop, and architecture outputs become continuously managed product requirements.

## 2026 Q2

### 1) Requirement Lifecycle Hardening
- Add optional helper script to upsert `SPR-*` entries from architecture review outputs.
- Add requirement ID collision checks and stale requirement detection.
- Add explicit risk-acceptance metadata template (approver, expiry, review date).

### 2) Cross-Skill Contract Validation
- Add contract linter for required fields:
  - `finding_id`
  - `severity`
  - `provenance`
  - `impacted_flow`
- Fail fast when architecture synthesis input violates contract.

### 3) Documentation and Examples
- Add end-to-end sample run package:
  - minimal producer outputs
  - synthesized architecture review
  - populated `security-product-requirements.md`

## 2026 Q3

### 1) CI Integration
- Add CI checks for:
  - markdown link validity
  - schema validation for sample JSONs
  - skill structure consistency (references/schemas/scripts presence)

### 2) Scenario and Flow Traceability
- Add machine-readable mapping export:
  - scenario -> finding -> flow -> requirement
- Add drift check that flags requirements not linked to current scenarios/findings.

### 3) Packaging
- Add release packaging profile:
  - tagged bundle zip
  - checksums
  - release metadata for offline distribution.

## 2026 Q4

### 1) Feedback Loop Automation
- Add generator for producer follow-up task lists from architecture gaps.
- Add status roll-up dashboard material (markdown/json) for leadership review.

### 2) Multi-Repo Program View
- Add portfolio-level guidance for combining multiple service architecture reviews.
- Standardize cross-service flow IDs and requirement aggregation strategy.

## Backlog Candidates

- Threat model profile templates by system type (API gateway, mobile backend, auth server).
- Optional SBOM-aware prioritization in static/external producers.
- Common glossary and naming conventions for scenario/flow/requirement IDs.
