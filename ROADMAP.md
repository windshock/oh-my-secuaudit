# Roadmap

## Direction

Keep this repository as a lightweight Codex/Claude skill collection, while ensuring output contracts are reproducible and continuously validated.

## Current Plan: Level 2 (Team Sharing + Minimum Reproducibility)

### Goals

1. Provide one end-to-end example set that new users can understand quickly.
2. Validate not only schema file existence, but also that sample outputs pass schemas.
3. Keep CI minimal: `validate + examples validate`.
4. Reduce confusion and duplication only where safe, without large refactors.

### Out of Scope (This Phase)

- No `secuaudit` CLI framework.
- No release bundling / containerization.
- No full architect auto-synthesis engine.
- No major schema renaming/refactor wave.
- No broad quality gate expansion (`ruff`, `mypy`, etc.).

## 2026 Q2 (Level 2 Execution)

### 1) Quickstart and End-to-End Example Package

- Add `examples/end-to-end-run/` with:
  - `README.md`
  - `inputs/static`, `inputs/runtime`, `inputs/external`
  - `outputs/static/task_output.json`
  - `outputs/runtime/task_output.json`
  - `outputs/external/task_output.json`
  - `outputs/reporting_summary.json`
  - optional `outputs/architect/*` placeholders
- Keep sample outputs minimal (1-2 findings each) but contract-accurate:
  - `severity`
  - `provenance`
  - `impacted_flow`

### 2) Validator Upgrade (Minimal but Strong)

- Extend `scripts/validate_skills_repo.py`:
  - validate schema files with `jsonschema` (schema self-validation)
  - add `--with-examples` option for validating sample output files
- Initial examples-to-schema mapping can be explicit/hardcoded.

### 3) CI Minimal Expansion

- Update `.github/workflows/ci.yml` to run:
  - dependency install (`jsonschema`)
  - `python3 scripts/validate_skills_repo.py --with-examples`
- Do not add heavyweight test/lint jobs in this phase.

### 4) Safe Deduplication Only (Optional)

- Consider deduping identical `generate_reporting_summary.py` scripts.
- Apply only if no skill UX regression occurs.
- If workflow ergonomics degrade, postpone deduplication.

## Done Definition (Level 2 Exit Criteria)

- `examples/end-to-end-run` exists with usage README.
- `python3 scripts/validate_skills_repo.py --with-examples` passes locally.
- CI blocks merge when the above validation fails.
- Team members can copy/extend sample JSON outputs for their own assessments.

## Expected Impact

- Moves the repo from "skill directories only" to a sample-backed, contract-validated skill repository.
- Preserves lightweight skill-first operation without over-engineering.

## Next (Post-Level 2 Candidates)

- Requirement lifecycle hardening (`SPR-*` collision/staleness checks).
- Scenario -> finding -> flow -> requirement machine-readable mapping.
- Multi-repo portfolio aggregation guidance.
