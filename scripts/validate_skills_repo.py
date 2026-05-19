#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_SKILLS = [
    ROOT / "plugins/oh-my-secuaudit/skills/sec-audit-static",
    ROOT / "plugins/oh-my-secuaudit/skills/sec-cluster",
    ROOT / "plugins/oh-my-secuaudit/skills/sec-audit-dast",
    ROOT / "plugins/oh-my-secuaudit/skills/external-software-analysis",
    ROOT / "plugins/oh-my-secuaudit/skills/security-architecture-review",
    ROOT / "plugins/oh-my-secuaudit/skills/security-testing-as-code",
]

PRODUCER_SKILLS = [
    ROOT / "plugins/oh-my-secuaudit/skills/sec-audit-static",
    ROOT / "plugins/oh-my-secuaudit/skills/sec-audit-dast",
    ROOT / "plugins/oh-my-secuaudit/skills/external-software-analysis",
]

REQUIRED_PRODUCER_SCHEMAS = [
    "schemas/reporting_summary_schema.json",
    "schemas/finding_schema.json",
    "schemas/task_output_schema.json",
]

REQUIRED_REVIEW_FILES = [
    "references/security_product_requirements_template.md",
    "schemas/security_product_requirement_schema.json",
    "schemas/architecture_handoff_schema.json",
]

REQUIRED_CLUSTER_FILES = [
    "schemas/cluster_metadata_schema.json",
]

# Common finding-base contract enforced across all three producer finding schemas.
# See docs/decisions/0001-shared-finding-schema.md and 0003-provenance-token-economy.md.
COMMON_FINDING_REQUIRED = [
    "id",
    "title",
    "severity",
    "category",
    "description",
    "provenance",
    "impacted_flow",
]
CANONICAL_SEVERITY_ENUM = ["Critical", "High", "Medium", "Low", "Info"]
CANONICAL_PROVENANCE_ENUM = [
    "binary-confirmed",
    "source-confirmed",
    "runtime-confirmed",
    "not-confirmed",
]
# ADR-0005 finding-level status enum. Optional field, but if declared must match.
CANONICAL_FINDING_STATUS_ENUM = [
    "confirmed",
    "needs-manual-review",
    "false-positive",
    "fixed",
    "deferred",
]

# Common task-output top-level required keys (looser than finding base).
COMMON_TASK_OUTPUT_REQUIRED = ["task_id", "status", "findings", "metadata"]
COMMON_TASK_OUTPUT_METADATA_REQUIRED = [
    "source_repo_url",
    "source_repo_path",
    "source_modules",
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_json(path: Path, errors: list[str]) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Invalid JSON: {path.relative_to(ROOT)} ({exc})")
        return None


def check_finding_schema_base(
    schema_path: Path, schema: dict, errors: list[str]
) -> None:
    """Enforce the common finding base on a producer's finding_schema.json."""
    rel = schema_path.relative_to(ROOT)
    items = (
        schema.get("properties", {})
        .get("findings", {})
        .get("items", {})
    )
    if not items:
        errors.append(f"{rel}: missing findings.items definition")
        return

    required = items.get("required", [])
    missing = [k for k in COMMON_FINDING_REQUIRED if k not in required]
    if missing:
        errors.append(
            f"{rel}: findings.items.required missing common base keys: {missing}"
        )

    props = items.get("properties", {})

    sev_enum = props.get("severity", {}).get("enum")
    if sev_enum != CANONICAL_SEVERITY_ENUM:
        errors.append(
            f"{rel}: severity enum does not match canonical "
            f"(expected {CANONICAL_SEVERITY_ENUM}, got {sev_enum})"
        )

    prov_enum = props.get("provenance", {}).get("enum")
    if prov_enum != CANONICAL_PROVENANCE_ENUM:
        errors.append(
            f"{rel}: provenance enum does not match canonical "
            f"(expected {CANONICAL_PROVENANCE_ENUM}, got {prov_enum})"
        )

    if "status" in props:
        status_enum = props["status"].get("enum")
        if status_enum != CANONICAL_FINDING_STATUS_ENUM:
            errors.append(
                f"{rel}: finding-level status enum does not match canonical "
                f"(expected {CANONICAL_FINDING_STATUS_ENUM}, got {status_enum})"
            )


def check_task_output_schema_base(
    schema_path: Path, schema: dict, errors: list[str]
) -> None:
    rel = schema_path.relative_to(ROOT)
    top_required = schema.get("required", [])
    missing = [k for k in COMMON_TASK_OUTPUT_REQUIRED if k not in top_required]
    if missing:
        errors.append(f"{rel}: top-level required missing: {missing}")

    metadata = schema.get("properties", {}).get("metadata", {})
    md_required = metadata.get("required", [])
    md_missing = [
        k for k in COMMON_TASK_OUTPUT_METADATA_REQUIRED if k not in md_required
    ]
    if md_missing:
        errors.append(
            f"{rel}: metadata.required missing common keys: {md_missing}"
        )


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
                errors.append(
                    f"Missing producer schema: {schema_path.relative_to(ROOT)}"
                )
                continue
            schema_obj = validate_json(schema_path, errors)
            if schema_obj is None:
                continue
            if schema_rel.endswith("finding_schema.json"):
                check_finding_schema_base(schema_path, schema_obj, errors)
            elif schema_rel.endswith("task_output_schema.json"):
                check_task_output_schema_base(schema_path, schema_obj, errors)

    review_dir = ROOT / "plugins/oh-my-secuaudit/skills/security-architecture-review"
    for rel in REQUIRED_REVIEW_FILES:
        path = review_dir / rel
        if not path.exists():
            errors.append(f"Missing review lifecycle asset: {path.relative_to(ROOT)}")
        elif rel.endswith(".json"):
            validate_json(path, errors)

    cluster_dir = ROOT / "plugins/oh-my-secuaudit/skills/sec-cluster"
    for rel in REQUIRED_CLUSTER_FILES:
        path = cluster_dir / rel
        if not path.exists():
            errors.append(f"Missing cluster asset: {path.relative_to(ROOT)}")
        elif rel.endswith(".json"):
            validate_json(path, errors)

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

    recon_dir = ROOT / "plugins/oh-my-secuaudit/skills/security-architecture-recon"
    if recon_dir.exists():
        errors.append("Deprecated skill directory still present: skills/security-architecture-recon")

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
