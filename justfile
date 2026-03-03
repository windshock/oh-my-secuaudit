set shell := ["/bin/bash", "-c"]

root := justfile_directory()

# Validate skill structure, schemas, and cross-skill contract assumptions
check:
    python3 {{root}}/scripts/validate_skills_repo.py

# Same as check, for CI naming symmetry
ci-check: check

# Quick repository status overview
status:
    git status --short
