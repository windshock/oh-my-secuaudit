# Release Guide

This repository ships skill definitions and schemas, so release quality depends on contract consistency across skills.

## Prerequisites

1. Local changes are committed on `main`.
2. Validation passes:
   - `just check`
   - or `python3 scripts/validate_skills_repo.py`
3. `RELEASE_NOTES.md` includes the upcoming version changes.

## Versioning

Use semantic version tags:

- `vMAJOR.MINOR.PATCH` (example: `v0.3.0`)

Suggested rules:

- `MAJOR`: breaking contract/layout changes across skills or schemas
- `MINOR`: backward-compatible capability additions
- `PATCH`: fixes, wording, or non-breaking workflow improvements

## Release Steps

1. Confirm working tree is clean.
2. Run validation:
   - `just check`
   - or `python3 scripts/validate_skills_repo.py`
3. Update `RELEASE_NOTES.md` with final version entry.
4. Commit:
   - `git add -A`
   - `git commit -m "chore: release vX.Y.Z"`
5. Tag:
   - `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
6. Push:
   - `git push origin main`
   - `git push origin vX.Y.Z`

The CI workflow (`.github/workflows/ci.yml`) is expected to pass on both `main` and the release tag context.
