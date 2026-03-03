#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_SKILLS = [
    ROOT / "skills/static/sec-audit-static",
    ROOT / "skills/runtime/sec-audit-dast",
    ROOT / "skills/external/external-software-analysis",
    ROOT / "skills/architect/security-architecture-review",
]

PRODUCER_SKILLS = [
    ROOT / "skills/static/sec-audit-static",
    ROOT / "skills/runtime/sec-audit-dast",
    ROOT / "skills/external/external-software-analysis",
]

REQUIRED_PRODUCER_SCHEMAS = [
    "schemas/reporting_summary_schema.json",
    "schemas/finding_schema.json",
    "schemas/task_output_schema.json",
]

REQUIRED_REVIEW_FILES = [
    "references/security_product_requirements_template.md",
    "schemas/security_product_requirement_schema.json",
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_json(path: Path, errors: list[str]) -> None:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Invalid JSON: {path.relative_to(ROOT)} ({exc})")


def main() -> int:
    errors: list[str] = []
    notes: list[str] = []

    for skill_dir in REQUIRED_SKILLS:
        if not skill_dir.exists():
            errors.append(f"Missing skill directory: {skill_dir.relative_to(ROOT)}")
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            errors.append(f"Missing SKILL.md: {skill_md.relative_to(ROOT)}")

    for skill_dir in PRODUCER_SKILLS:
        for schema_rel in REQUIRED_PRODUCER_SCHEMAS:
            schema_path = skill_dir / schema_rel
            if not schema_path.exists():
                errors.append(f"Missing producer schema: {schema_path.relative_to(ROOT)}")
                continue
            validate_json(schema_path, errors)

        finding_schema = skill_dir / "schemas/finding_schema.json"
        if finding_schema.exists():
            text = finding_schema.read_text(encoding="utf-8")
            if '"provenance"' not in text:
                errors.append(f"Missing 'provenance' in finding schema: {finding_schema.relative_to(ROOT)}")
            if '"impacted_flow"' not in text:
                errors.append(f"Missing 'impacted_flow' in finding schema: {finding_schema.relative_to(ROOT)}")

    review_dir = ROOT / "skills/architect/security-architecture-review"
    for rel in REQUIRED_REVIEW_FILES:
        path = review_dir / rel
        if not path.exists():
            errors.append(f"Missing review lifecycle asset: {path.relative_to(ROOT)}")

    shared_schema_paths = [
        p / "schemas/reporting_summary_schema.json"
        for p in PRODUCER_SKILLS
        if (p / "schemas/reporting_summary_schema.json").exists()
    ]

    if len(shared_schema_paths) == 3:
        hashes = {p: sha256_file(p) for p in shared_schema_paths}
        unique_hashes = set(hashes.values())
        if len(unique_hashes) != 1:
            errors.append("reporting_summary_schema.json mismatch across producer skills")
            for path, digest in hashes.items():
                notes.append(f"  - {path.relative_to(ROOT)}: {digest}")
        else:
            digest = next(iter(unique_hashes))
            notes.append(f"Shared reporting_summary_schema hash: {digest}")

    recon_dir = ROOT / "skills/architect/security-architecture-recon"
    if recon_dir.exists():
        errors.append("Deprecated skill directory still present: skills/architect/security-architecture-recon")

    if errors:
        print("[FAIL] skills repository validation failed")
        for err in errors:
            print(f"- {err}")
        if notes:
            print("[NOTES]")
            for note in notes:
                print(note)
        return 1

    print("[OK] skills repository validation passed")
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
