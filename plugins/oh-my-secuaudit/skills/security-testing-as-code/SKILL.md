---
name: security-testing-as-code
description: Transform security assessment deliverables from static documents (Word/Excel/portal) into version-controlled, executable projects. PoCs replace narrative claims; saved HTTP requests replace checkboxes; commit hashes enable exact-state reproduction. Use when scoping methodology for an audit, when an existing assessment needs to be made reproducible, or when assessment outputs must be inheritable across teams.
---

# security-testing-as-code: Assessment as Executable Project

Transform security assessment deliverables from static documents into version-controlled, executable projects. Findings become reproducible code; evidence becomes artifacts; knowledge becomes inheritable structure.

## Core Thesis

> "A diagnosis is a document" is the fundamental flaw. A diagnosis should be a project.

Traditional security reports (Word, Excel, portal entries) produce ephemeral knowledge that dies upon publication. This skill converts assessment outputs into living, version-controlled projects where:

- PoC code replaces narrative claims
- Saved HTTP requests replace "verified" checkboxes
- Commit hashes enable exact state reproduction
- Handoff plans replace tribal knowledge

## When to Use

- After completing any producer skill (`sec-audit-static`, `sec-audit-dast`, `external-software-analysis`)
- When packaging findings for developer handoff
- When building a reproducible evidence chain for compliance
- When multiple assessment cycles target the same system (inheritable structure)

## Inputs

- Findings from any producer skill (JSON, SARIF, markdown)
- PoC code or exploit scripts developed during assessment
- HTTP request/response captures
- Threat intelligence or preliminary research notes
- Previous assessment artifacts (for delta/handoff)

## Project Structure

Every assessment produces a self-contained project directory:

```
assessment/
├── README.md                  ← Overall context, progress status, how to run
├── handoff-plan.md            ← Gap analysis, inheritance specs for next assessor
├── analysis/
│   ├── attack-surface/        ← Endpoint/integration/asset inventory
│   ├── findings/              ← Structured finding records (JSON/markdown)
│   └── threat-model/          ← DFD, trust boundaries, attack scenarios
├── artifacts/
│   ├── poc/                   ← Reproducible PoC code per finding
│   │   ├── <finding-id>/      ← One directory per PoC
│   │   │   ├── README.md      ← Setup, run instructions, expected output
│   │   │   ├── exploit.*      ← Exploit code (any language)
│   │   │   ├── Dockerfile     ← (optional) Reproducible environment
│   │   │   └── evidence/      ← Screenshots, logs from successful run
│   │   └── ...
│   └── runtime/               ← HTTP evidence, config snapshots
│       ├── requests/          ← Saved HTTP request/response pairs
│       ├── configs/           ← Captured service configurations
│       └── scans/             ← Tool output (Semgrep, nuclei, etc.)
├── inputs/
│   ├── threat-intel/          ← Advisory research, CVE/KEV context
│   ├── scope/                 ← Engagement scope, target definitions
│   └── prior-assessments/     ← Previous cycle artifacts (for delta)
└── outputs/
    ├── report.md              ← Final narrative report
    ├── finding_summary.json   ← Machine-readable finding index
    └── reporting_summary.json ← Cross-skill reporting summary
```

## Workflow

### Phase 1: Initialize Project Structure

1. Create the directory tree above.
2. Populate `README.md` with:
   - Assessment scope and target description
   - Date, assessor, engagement ID
   - How to reproduce findings (prerequisites, environment setup)
   - Current status (in-progress / complete / handed-off)
3. Populate `inputs/scope/` with engagement boundaries.

### Phase 2: Capture Attack Surface

1. Run discovery tools and save raw output to `artifacts/runtime/scans/`.
2. Synthesize into `analysis/attack-surface/` inventory:
   - Endpoint list with auth requirements
   - Integration points (external services, APIs)
   - Technology stack and versions
3. Cross-reference with prior assessments if available in `inputs/prior-assessments/`.

### Phase 3: Evidence-Driven Finding Documentation

For each finding:

1. **Create finding record** in `analysis/findings/`:
   ```json
   {
     "id": "FINDING-001",
     "title": "XSS in search parameter",
     "severity": "High",
     "category": "XSS",
     "provenance": "source-confirmed",
     "impacted_flow": ["F1"],
     "evidence_path": "artifacts/poc/FINDING-001/",
     "status": "confirmed"
   }
   ```

2. **Build PoC** in `artifacts/poc/FINDING-001/`:
   - Executable code that demonstrates the vulnerability
   - `README.md` with exact reproduction steps
   - `evidence/` with captured output from successful execution
   - Optional `Dockerfile` for environment isolation

3. **Save runtime evidence** in `artifacts/runtime/requests/`:
   - HTTP request/response pairs (curl commands, .http files, or HAR)
   - Configuration snapshots showing vulnerable settings
   - Tool scan output confirming the finding

### Phase 4: PoC Quality Standards

Every PoC must meet these criteria:

| Criterion | Requirement |
|---|---|
| **Reproducible** | Another assessor can run it and get the same result |
| **Self-contained** | All dependencies documented or containerized |
| **Non-destructive** | Safe to run against target (no data loss, no DoS) |
| **Documented** | README explains what it proves and what "success" looks like |
| **Versioned** | Tied to a specific commit/state of the target |

PoC types by finding category:

| Category | PoC Format | Example |
|---|---|---|
| Injection (XSS/SQLi) | Payload + request capture | curl command + response showing injection |
| Fuzzing discovery | Fuzzer config + corpus + crash log | Jazzer/AFL harness + evidence |
| Auth bypass | Test script with two scenarios | With auth vs without auth comparison |
| Deserialization | Gadget chain + trigger | Payload generator + server response |
| Config weakness | Config diff + impact demo | Vulnerable vs hardened config comparison |

### Phase 5: Handoff Plan

Create `handoff-plan.md` documenting:

1. **Completed scope**: What was tested, what evidence exists
2. **Open gaps**: What was NOT tested and why
   - Time constraints
   - Access limitations
   - Environment unavailability
3. **Recommended next steps**: Prioritized by risk
4. **Environment notes**: How to set up the test environment
5. **Credential/access notes**: What access is needed (without storing actual credentials)
6. **Known false positive patterns**: Save future assessors from re-investigating

### Phase 6: Output Generation

1. Generate `outputs/report.md` — narrative report with links to artifacts
2. Generate `outputs/finding_summary.json` — machine-readable index
3. Generate `outputs/reporting_summary.json` — compatible with `sec-audit-static` reporting schema
4. Ensure all artifact paths are relative (portable across machines)

## Medical Records Metaphor

| Concept | Medical Certificate (bad) | Medical Records (good) |
|---|---|---|
| Nature | One-time result snapshot | Progressive, inheritable documentation |
| Reproduction | "Trust me, I checked" | "Run this command, see this output" |
| Handoff | Start from scratch | Continue from documented state |
| Version | None | Git commit = exact state |
| Knowledge | Dies with the author | Lives in the repository |

## Integration with Other Skills

| Skill | Integration Point |
|---|---|
| `sec-audit-static` | Findings become `analysis/findings/`, tool outputs go to `artifacts/runtime/scans/` |
| `sec-audit-dast` | SARIF outputs go to `artifacts/runtime/scans/`, probes become PoCs |
| `external-software-analysis` | Binary analysis notes go to `analysis/`, decompilation artifacts preserved |
| `sec-cluster` | Cluster definitions inform `analysis/attack-surface/` organization |
| `security-architecture-review` | DFD/attack flow go to `analysis/threat-model/`, SPRs reference finding IDs |

## Anti-Patterns to Avoid

| Anti-Pattern | Why It's Bad | Do This Instead |
|---|---|---|
| Screenshot-only evidence | Not reproducible, not searchable | Save the actual request/response + command |
| "Verified" without artifacts | Unverifiable claim | Link to PoC directory with run instructions |
| Findings in report only | Lost when report format changes | Structured JSON + markdown + PoC code |
| Hardcoded absolute paths | Breaks on another machine | Use relative paths from project root |
| Credentials in artifacts | Security risk | Reference credential store, never embed |

## Resources

- `references/project_structure.md` — Detailed directory layout reference
- `references/poc_standards.md` — PoC quality and safety guidelines
- `templates/assessment/` — Starter project template (copy to begin)
- `templates/finding.json` — Finding record template
- `templates/poc-readme.md` — PoC README template
- `templates/handoff-plan.md` — Handoff plan template

## Related Reading

- [Security Diagnostics Reports Die Upon Publication](https://windshock.github.io/en/post/2026-03-17-security-testing-as-code/) — Origin thesis for this skill
