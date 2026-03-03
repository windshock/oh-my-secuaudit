# oh-my-secuaudit

Security skill collection for Codex-style workflows.

## Layout

- `skills/static/sec-audit-static`: static security audit workflow (SAST/SCA/secret/reporting)
- `skills/runtime/sec-audit-dast`: runtime/API assessment workflow (DAST/ASM)
- `skills/external/external-software-analysis`: third-party software/binary analysis workflow
- `skills/architect/security-architecture-review`: security architecture review workflow

## Capability Matrix

| Skill | Primary Question | Typical Input | Primary Output | Consumed By |
|---|---|---|---|---|
| `sec-audit-static` | What is vulnerable in source code and dependencies? | source repo | finding JSON, task/final report JSON, markdown report, `reporting_summary` | `security-architecture-review` |
| `sec-audit-dast` | What is exposed or exploitable at runtime? | domains/IPs/endpoints/ASM exports | SARIF/CSV findings, finding JSON, `reporting_summary` | `security-architecture-review` |
| `external-software-analysis` | What risks exist in third-party binaries/packages? | jar/aar/so/external package | markdown report, finding JSON, architecture handoff markdown, `reporting_summary` | `security-architecture-review` |
| `security-architecture-review` | How do all findings affect trust boundaries and critical flows? | static/dast/external outputs + repo evidence | `security-architecture-review.md` + `security-product-requirements.md` (tracked backlog and lifecycle delta) | final artifact |

## End-to-End Relationship Map

```mermaid
flowchart LR
    subgraph L0["Layer 0: Threat Context (Manual, Non-Automated)"]
        T["External threat research (advisories, KEV/CVE trends, abuse intel)"]
    end

    subgraph L1["Layer 1: Producer Runs"]
        S["sec-audit-static"]
        D["sec-audit-dast"]
        E["external-software-analysis"]
    end

    subgraph L2["Layer 2: Contract Normalization"]
        N["Normalize findings: finding_id, severity, provenance, impacted_flow"]
    end

    subgraph L3["Layer 3: Architecture Synthesis"]
        R["security-architecture-review"]
    end

    subgraph L4["Layer 4: Outputs and Lifecycle"]
        O["security-architecture-review.md"]
        P["security-product-requirements.md (SPR backlog + delta)"]
        FB["Feedback scope: missing evidence, boundary gaps, flow-specific follow-up"]
    end

    S -->|required| N
    D -->|required| N
    E -->|required| N
    E -.->|optional enrichment| EH["external-analysis-architecture-handoff.md"]
    T -.->|manual threat context| R

    N -->|required| R
    EH -.->|optional enrichment| R

    R -->|required| O
    R <--> |continuous requirement lifecycle| P

    O -->|gap-based follow-up| FB
    P -->|SPR-driven priorities| FB

    FB -.->|targeted re-scan| S
    FB -.->|targeted re-scan| D
    FB -.->|targeted re-analysis| E
    FB -.->|new threat questions| T

    classDef static fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20;
    classDef runtime fill:#fff3e0,stroke:#ef6c00,color:#e65100;
    classDef external fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;
    classDef threat fill:#ffebee,stroke:#c62828,color:#b71c1c;
    classDef review fill:#fff8e1,stroke:#f9a825,color:#e65100;
    classDef contract fill:#eceff1,stroke:#455a64,color:#263238;
    classDef artifact fill:#f5f5f5,stroke:#616161,color:#212121;
    classDef feedback fill:#e0f2f1,stroke:#00695c,color:#004d40;

    class T threat;
    class S static;
    class D runtime;
    class E,EH external;
    class N contract;
    class R review;
    class O,P artifact;
    class FB feedback;
```

Legend:
- Green: static producer flow
- Orange: runtime producer flow
- Blue: external producer flow
- Red: external threat context (manual/non-automated input)
- Yellow: architecture synthesis
- Gray: contract normalization and artifacts
- Teal: feedback loop to producers
- Solid arrow: required handoff
- Dashed arrow: optional enrichment or iterative feedback
- Double arrow: continuous lifecycle synchronization

## Handoff Contract (Why It Matters)

- `security-architecture-review` is not another scanner.
- It is the synthesis layer that merges heterogeneous evidence and decides:
  - which risks are architecture-confirmed
  - which are external/runtime-only
  - which remain `not-confirmed`
- Cross-skill normalization relies on these fields:
  - `finding_id` (or `id`)
  - `severity`
  - `provenance` (`binary-confirmed|source-confirmed|runtime-confirmed|not-confirmed`)
  - `impacted_flow` (e.g. `F1`, `F2`)

## Minimal Artifact Set For Architecture Review

| Source Skill | Required For Synthesis | Recommended |
|---|---|---|
| `sec-audit-static` | finding JSON with required fields, `reporting_summary` | markdown report and taint/source-sink notes |
| `sec-audit-dast` | finding JSON or normalized runtime findings with required fields, `reporting_summary` | SARIF and reproducible probe metadata |
| `external-software-analysis` | finding JSON with required fields | `external-analysis-architecture-handoff.md` |
| external threat research (manual) | not required for run completion | threat themes from advisories/intel mapped to attack scenarios |

## Architecture-to-Product Bridge

- `security-architecture-review` converts High/Critical risks and unresolved gaps into `SPR-*` requirements.
- Each `SPR-*` must include owner, target milestone, status, and testable acceptance criteria.
- Requirement status is updated on every architecture run with a delta:
  - `added`, `updated`, `closed`, `deferred`, `accepted-risk`

## Which Skills To Run

| Situation | Run |
|---|---|
| Source repository audit | `sec-audit-static` -> `security-architecture-review` |
| External endpoint/runtime assessment | `sec-audit-dast` -> `security-architecture-review` |
| Third-party binary/package risk | `external-software-analysis` -> `security-architecture-review` |
| Full blended assessment | `sec-audit-static` + `sec-audit-dast` + `external-software-analysis` -> `security-architecture-review` |

## Recommended Orchestration

1. Run producer skills (`static`, `runtime`, `external`) in parallel where possible.
2. Normalize findings with the common contract (`finding_id`, `severity`, `provenance`, `impacted_flow`).
3. Add manual external threat research themes and map them to candidate attack scenarios.
4. Run `security-architecture-review` to map findings into DFD nodes, trust boundaries, and attack scenarios.
5. Generate a feedback plan from architecture gaps (missing evidence, unresolved boundaries, uncertain flows, new threat questions).
6. Re-run producers with focused scope from the feedback plan, then re-run architecture review.
7. Upgrade `provenance` only when new direct evidence exists.

## Closed-Loop Model (Producer <-> Architecture)

1. Producers find candidates and initial confirmations.
2. Architecture review synthesizes system-level risk and identifies confirmation gaps.
3. Gaps are translated into targeted producer actions (new rules, new probes, deeper binary/source tracing).
4. Producers return refined evidence.
5. Architecture review updates DFD/Attack Flow and confidence.
6. Repeat until major gaps are closed.

## Quality Gates Before Final Report

1. Every imported finding has `provenance` and `impacted_flow`.
2. External runtime-hop components (e.g. RP relay, mobile SDK) appear explicitly in DFD node/edge/boundary mapping.
3. Attack Flow scenarios map back to scenario IDs and imported finding IDs.
4. `Confidence & Gaps` clearly lists unresolved confirmation items.

## Developer Workflow

- Run local validation: `just check` (or `python3 scripts/validate_skills_repo.py`)
- CI runs the same contract validation on `push`/`pull_request` to `main`.
- Quick working tree check: `just status`

Release process:
- See [`.github/RELEASE_GUIDE.md`](.github/RELEASE_GUIDE.md) for versioning/tagging steps.

## Project Docs

- Release notes: `RELEASE_NOTES.md`
- Future plan: `ROADMAP.md`

## Notes

- Each skill directory contains its own `SKILL.md`, references, schemas, and scripts.
- Skills are separated by domain under `skills/static`, `skills/runtime`, `skills/external`, and `skills/architect`.
