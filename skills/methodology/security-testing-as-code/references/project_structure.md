# Assessment Project Structure Reference

## Directory Layout

```
assessment/
├── README.md
├── handoff-plan.md
├── analysis/
│   ├── attack-surface/
│   │   ├── endpoints.md          ← API/endpoint inventory with auth requirements
│   │   ├── integrations.md       ← External service dependencies
│   │   └── tech-stack.md         ← Technology versions and components
│   ├── findings/
│   │   ├── FINDING-001.json      ← Structured finding records
│   │   ├── FINDING-002.json
│   │   └── index.md              ← Finding summary with cross-references
│   └── threat-model/
│       ├── dfd.mmd               ← Data flow diagram (Mermaid)
│       ├── trust-boundaries.md   ← Trust boundary definitions
│       └── attack-scenarios.md   ← AS-* scenario descriptions
├── artifacts/
│   ├── poc/
│   │   ├── FINDING-001/
│   │   │   ├── README.md         ← Reproduction steps
│   │   │   ├── exploit.py        ← PoC code
│   │   │   ├── Dockerfile        ← (optional) Environment isolation
│   │   │   └── evidence/
│   │   │       ├── output.txt    ← Captured exploit output
│   │   │       └── screenshot.png← (optional) Visual evidence
│   │   └── FINDING-002/
│   │       └── ...
│   └── runtime/
│       ├── requests/
│       │   ├── finding-001.http  ← HTTP request/response pairs
│       │   └── finding-002.http
│       ├── configs/
│       │   └── target-nginx.conf ← Captured configurations
│       └── scans/
│           ├── semgrep-output.json
│           ├── nuclei-output.json
│           └── nmap-results.xml
├── inputs/
│   ├── threat-intel/
│   │   └── relevant-cves.md     ← Advisory/CVE context
│   ├── scope/
│   │   ├── engagement-brief.md  ← Scope definition
│   │   └── target-list.md       ← IPs, domains, repos
│   └── prior-assessments/
│       └── 2025-q4-summary.md   ← Previous cycle reference
└── outputs/
    ├── report.md                ← Final narrative report
    ├── finding_summary.json     ← Machine-readable finding index
    └── reporting_summary.json   ← Cross-skill reporting summary
```

## File Naming Conventions

| Type | Pattern | Example |
|---|---|---|
| Finding record | `FINDING-NNN.json` | `FINDING-001.json` |
| PoC directory | `FINDING-NNN/` | `FINDING-001/` |
| HTTP evidence | `finding-NNN.http` | `finding-001.http` |
| Scan output | `<tool>-output.<format>` | `semgrep-output.json` |

## Path Rules

- All artifact paths in finding records MUST be relative to the project root.
- Never embed absolute paths — the project must be portable across machines.
- Never store credentials, tokens, or secrets in any file. Reference an external credential store.

## Git Conventions

- Each finding's PoC should be committed atomically (one commit per finding when practical).
- Commit messages reference finding IDs: `add PoC for FINDING-001: XSS in search param`.
- Tag assessment milestones: `v1.0-initial`, `v1.1-retest`, `v2.0-annual`.
