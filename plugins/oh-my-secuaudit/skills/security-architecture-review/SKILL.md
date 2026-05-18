---
name: security-architecture-review
description: Security architecture review for codebases, producing Data Flow Diagram (DFD) with trust boundaries, Attack Flow overlay, scoped attack surface inventory, sensitive data map, and risk summary grounded in code. Use when asked to perform architecture-focused security review, reconstruct security design from code, or produce DFD/attack-flow documentation.
---

# Security Architecture Review

## Purpose
Produce architecture-focused security review artifacts from code: DFD with trust boundaries, Attack Flow overlay, attack surface inventory, sensitive data map, and risk summary. Keep claims tied to code locations and runtime verification only when explicitly requested.

## Workflow

### 1) Scope and Inputs
- Confirm target modules and repositories.
- Identify entry points (HTTP, messaging, batch, schedulers) and data stores.
- Note external integrations (CDN, third-party APIs, storage).
- Capture service purpose/business context from README/docs/ops notes.
- If the service purpose is unclear, state it and add questions for confirmation.
- Expect to refine the service purpose after initial code inspection; update the purpose section accordingly.

### 2) Attack Surface Inventory
- Enumerate endpoints and exposure types with method, inputs, outputs, auth.
- Include operational endpoints and batch triggers.
- Prioritize critical surface areas using threat-led criteria (high-value state changes, external integrations, auth boundaries, batch/automation paths, sensitive data handling). If a full list is large, list critical ones in the main section and move the remainder to an appendix.

### 2.1) Discovery Traceability (When doing zero-day style analysis)
- Record the discovery path, not only final findings:
  - Which tools were used (e.g., decompiler, SAST, grep, code graph)
  - Candidate narrowing logic (why some findings were dropped/promoted)
  - Key command options/rulesets that materially affected results
- Keep this concise in the main body and move raw command/output details to an appendix.

### 2.2) Cross-Repository Call-Chain Reconstruction (When applicable)
- If vulnerability relevance depends on integration path, reconstruct end-to-end call chain across repos/services.
- Prefer explicit chain notation (e.g., `App -> Gateway -> API -> Library -> Target Service`).
- Mark each hop as:
  - `confirmed in code` (with file evidence), or
  - `not confirmed in code` (assumption/interview needed).
- Include at least one sequence diagram for critical business/security flows when multi-hop routing is central to risk.

### 2.3) Interop with `external-software-analysis` (When third-party binaries are in scope)
- If key findings come from decompiled binaries/packages (`jar/aar/so`), consume the external analysis handoff artifact first.
- Expected handoff inputs:
  - External analysis markdown report
  - `reporting_summary` JSON
  - Architecture handoff markdown (preferred: `external-analysis-architecture-handoff.md`)
- For each imported claim, keep provenance explicitly:
  - `binary-confirmed`, `source-confirmed`, `runtime-confirmed`, `not-confirmed`
- Re-map imported findings into:
  - DFD node/boundary impact
  - Attack Flow abuse path
  - Attack Scenario row with confirmation needs
- If an imported finding is tied to a runtime hop (for example relay/proxy/sdk/backend component), add that component as an explicit DFD node and edge.
- Do not collapse such components into a generic node like `App` or `External`.
- Do not upgrade confidence from `binary-confirmed` to `source-confirmed` without direct source evidence.

### 2.4) Final Synthesis Contract (Across static/external/dast)
- For machine-readable finding inputs, require these common fields:
  - `finding_id` (or equivalent `id`)
  - `provenance` (`binary-confirmed|source-confirmed|runtime-confirmed|not-confirmed`)
  - `impacted_flow` (array of flow IDs such as `F1`, `F2`)
  - `severity`
- Prefer the shared `reporting_summary_schema.json` format from static/dast/external skills when ingesting run summaries.
- If any source omits `provenance` or `impacted_flow`, keep the finding as `not-confirmed` and record a confirmation gap.
- For High/Critical findings, map each item to at least one security product requirement (`SPR-*`) or record an explicit risk-acceptance reason.

### 2.5) Existing Vulnerability Report Intake (Markdown)
- Treat existing reports (for example `vuln_report_*.md`) as first-class architecture inputs.
- For each imported report, extract and normalize:
  - `finding_id` (stable slug)
  - vulnerability family (`deserialization`, `crypto-oracle`, `authz`, etc.)
  - Source->Sink or exploit-path summary
  - code evidence paths
  - runtime/PoC evidence artifacts
  - mitigation summary
- Map each imported finding to architecture context:
  - impacted DFD node/boundary
  - impacted attack scenario
  - `provenance` and `impacted_flow`
- If a report is library-only or ecosystem-only and no service path is confirmed, keep service impact as `not-confirmed` and list it as a candidate external threat.

### 3) DFD + Trust Boundaries
- Build a DFD that reflects actual code paths.
- Use explicit trust boundaries. Prefer nesting internal boundaries inside external ones.
- Distinguish internal services, external clients, and third-party APIs.
- Represent trust boundaries as Mermaid `subgraph` zones (for example `Boundary B1: Internet Client Zone`), not as standalone boundary label nodes.
- Express trust-boundary crossings via edges that traverse zones; avoid pseudo-links such as `TB1 --- App`.
- Keep node labels concise and stable.
- Keep batch/indexing boundaries separate from logging/messaging unless code shows a direct control or runtime coupling.
- If the DFD feels too flat, add a minimal set of core process nodes (e.g., OrderProc, CouponProc, ManualProc, BatchProc) to clarify data flow between entry points and data stores without over-complicating the diagram.
- Apply a consistent inclusion filter when expanding DFD scope: include modules that handle state-changing operations, external integrations, authentication/authorization boundaries, batch/automation paths, or sensitive data handling. Avoid ad-hoc omissions.

### 4) Attack Flow Overlay
- Create an Attack Flow diagram based on known vulnerabilities or plausible abuse paths.
- Show attacker → exploit → control impact paths.
- Keep it separate from DFD but aligned to DFD nodes.
- Organize the diagram by scenario using `AS-xx` subgraphs instead of a single scattered graph.
- Prefer a compact 3-step chain per scenario: `Entry -> Weakness -> Impact`.
- Limit the main Attack Flow to the most security-significant scenarios; keep long-tail scenarios in the table.

### 4.1) Attack Scenarios
- Add an Attack Scenarios section after the Attack Flow diagram.
- For each scenario, map confirmed vulnerabilities to IDs when available.
- For uncertain scenarios, list the evidence or questions required to confirm.
- For each scenario, include both: (1) DFD-based normal flow and (2) Attack Flow-based abuse path.
- Prefer a scenario table with columns that capture flow, impact, and confirmation needs.

### 4.2) Protocol/Message Schema Mapping (When API payloads are risk-relevant)
- For critical flows, summarize request/response schema and trust-relevant fields.
- Identify where each field originates and where it is validated.
- Explicitly call out branch keys (e.g., `type`, `operation`, `transactionId`) that change control flow or authorization behavior.

### 4.3) Vulnerability Family Mapping
- Group findings/scenarios by vulnerability family (for example `deserialization`, `crypto-oracle`, `token/secret`, `trust-boundary bypass`).
- For each family, summarize:
  - required attacker preconditions
  - architecture-level impact (boundary crossed, trust assumption broken)
  - whether exploitation is confirmed in runtime or only inferred

### 4.4) PoC Evidence Binding (When PoC artifacts exist)
- For each confirmed or partially confirmed scenario, bind evidence explicitly:
  - `finding_id`
  - code-path evidence (file path + line)
  - runtime artifact (log, output, marker file, HTTP differential)
  - reproducer/script reference
- If one of the above is missing, keep or downgrade to `not-confirmed` for that layer and record the missing link.

### 5) Sensitive Data Map
- Identify secrets, credentials, PII, tokens, and where they flow or are stored.

### 6) Risk Summary
- List structural risks tied to architecture (not just code-level issues).
- Reference the most critical data flows and trust boundaries.

### 6.1) External Threat Landscape (Purpose-Based)
- Based on the service purpose, list external threat actors and abuse cases.
- Use sources like README, product docs, or ops notes. Avoid assumptions without evidence.
- Separate “confirmed in code/docs” vs “needs confirmation”.
- If a separate Deep Research document exists, map its threat themes to concrete scenarios and note the mapping explicitly.
- Use the external threat mapping to validate that all critical surfaces are covered in DFD/Attack Flow.

### 6.2) Security Product Requirements (SPR) Generation
- Convert architecture risks and confirmation gaps into actionable product requirements.
- Each requirement must be testable and owned.
- Minimum requirement fields:
  - `requirement_id` (stable, e.g., `SPR-001`)
  - `title`
  - `statement` (normative requirement)
  - `linked_scenarios` (e.g., `AS-01`, `AS-07`)
  - `linked_findings` (e.g., `F-PO-LOGIN-001`)
  - `priority` (`P0|P1|P2|P3`)
  - `owner` (team/service)
  - `target_milestone` (release/sprint/date)
  - `status` (`draft|planned|in_progress|blocked|done|deferred|accepted-risk`)
  - `acceptance_criteria` (verifiable checks)
  - `verification_evidence` (PR/test/report links once available)
  - `last_reviewed_at` (YYYY-MM-DD)

### 6.3) Continuous Requirement Lifecycle
- Maintain a persistent backlog file: `./security-product-requirements.md` (default).
- On every architecture review run:
  - Add new requirements for newly confirmed risks/gaps.
  - Update status/owner/milestone for existing requirements.
  - Close requirements only with verification evidence.
  - Mark unresolved items with blocking dependencies.
- Keep a review delta in the architecture report:
  - `added`, `updated`, `closed`, `deferred`, `accepted-risk`
- Feed unresolved gaps back to producer skills as targeted follow-up tasks.

### 7) High-Risk Analysis (Code-Based)
- For top-priority scenarios, add a short code-based analysis section:
  - Code evidence (file paths)
  - Risk summary
  - Confirmation needs (evidence/interview)
  - Architecture-level mitigations

### 8) Reporting Hygiene and Disclosure Safety
- Separate clearly:
  - discovery/analysis evidence, and
  - reproduction/PoC steps (if present).
- In architecture reviews, keep PoC details minimal unless explicitly requested.
- Before finalizing, redact or mask sensitive values (tokens, secrets, internal hostnames, account identifiers) when they are not necessary to communicate risk.
- Add a short “safe-sharing” note when the source artifacts include operational secrets.

## Output Requirements
- Provide:
  1. Scope and dependencies
  2. Attack surface inventory
  3. DFD summary
  4. Sensitive data map
  5. Trust boundaries and controls
  6. Risk summary
  7. DFD Mermaid
  8. Attack Flow Mermaid
  9. Attack Scenarios (with confirmed vs unconfirmed)
- In Attack Scenarios, include DFD flow + Attack Flow path per scenario and include confirmation needs.
- Use English labels in Mermaid.
- Align color/style classes across DFD and Attack Flow.
- Annotate uncertain items as “not confirmed in code”.
- In DFD Mermaid, boundaries must be rendered with `subgraph` blocks (`Boundary Bn: ...`), not boundary proxy nodes.
- For zero-day style engagements, also include:
  10. Discovery process summary (tools, narrowing decisions, confidence)
  11. Cross-repo call-chain mapping (if applicable)
  12. Protocol/message schema table for critical paths (if applicable)
  13. Safe-sharing notes (redaction/masking requirements when needed)
  14. External component findings mapping with provenance tags (if external analysis is used)
  15. Vulnerability family mapping table
  16. PoC evidence binding matrix (when PoC/runtime evidence is available)
  17. System-context DFD addendum for imported external components (component node + hop + trust boundary)
  18. Security Product Requirements backlog summary
  19. Requirements lifecycle delta (added/updated/closed/deferred/accepted-risk)

## Markdown Reporting (Required)
- Always create a Markdown report file as an output artifact, not only a chat response.
- Default output path: `./security-architecture-review.md` from the current workspace root.
- If the user provides a path/filename, use that path instead.
- Include at the top:
  - Report title
  - Date (YYYY-MM-DD)
  - Scope target (repo/service/module)
  - Analysis basis (code-only, runtime checks if any)
- Required file sections mirror Output Requirements 1-9.
- Keep Mermaid diagrams in fenced blocks with `mermaid` language tag.
- Keep evidence references as concrete file paths with line numbers where possible.
- Add a short final section:
  - `## Confidence & Gaps`
  - Explicitly list items marked “not confirmed in code”.
- When a process-oriented artifact exists (e.g., a zero-day discovery log), add:
  - `## Discovery Notes` (how findings were found/refined)
  - `## Evidence Coverage` (what is code-confirmed vs inferred)
- When prior vulnerability markdown reports are ingested (e.g., `vuln_report_*.md`), add:
  - `## Prior Vulnerability Inputs` (list of imported report files)
  - `## Imported Findings Mapping` (`finding_id -> scenario/DFD node + provenance + impacted_flow`)
  - `## Vulnerability Family Mapping`
  - `## PoC Evidence Binding`
- If imported findings include runtime hop components (e.g., RP relay, mobile SDK, external parser service), add:
  - `## System Context Addendum`
  - Per component: `component`, `role`, `incoming edge`, `outgoing edge`, `trust boundary`, `confirmation status`
- Always create or update `./security-product-requirements.md` unless the user provides another path.
- In the architecture report, include:
  - `## Security Product Requirements` (summary table)
  - `## Requirement Lifecycle Delta` (what changed in this run)
- Keep requirement IDs stable across runs (never recycle IDs).
- Optional machine-readable output: `security-product-requirements.json` validated against `schemas/security_product_requirement_schema.json`.
- When external binary analysis was used, add:
  - `## External Analysis Inputs` (files used from external-software-analysis)
  - `## Imported Findings Mapping` (finding_id -> DFD/Attack Scenario + provenance tag)
- In the final assistant response, include:
  - The created Markdown file path
  - A 1-3 line summary of key risks

## Completion Criteria (General)
Use these as the default “stop” conditions unless the user specifies otherwise:
1. All externally exposed functions (HTTP/API/console/batch/messaging) are identified.
2. For each function, inputs → processing → outputs are confirmed with code evidence.
3. Function-level data stores and external integrations are reflected in the DFD.
4. Attack Flow includes confirmed vulnerabilities and at least one plausible abuse path per major boundary.
5. Anything without code evidence is explicitly marked “not confirmed in code”.
6. Attack Scenarios table is complete for the major systems in scope.
7. Imported findings from prior reports are mapped to DFD/Attack Scenarios with `provenance` and `impacted_flow`.
8. For runtime-confirmed claims, at least one runtime artifact reference is captured.
9. If imported findings reference external runtime-hop components, those components are explicitly present in DFD (node + edges + boundary).
10. High/Critical risks are mapped to tracked security product requirements or documented as accepted-risk with rationale.
11. Requirement lifecycle delta is recorded for this run.

## Resources
- Template: `references/security_product_requirements_template.md`
- Schema: `schemas/security_product_requirement_schema.json`

## Diagram Conventions
- DFD uses `trusted`, `untrusted`, `neutral` classes for nodes.
- DFD trust boundaries are `subgraph` blocks with explicit boundary titles (`Boundary B1`, `Boundary B2`, ...).
- Do not model trust boundaries as standalone nodes (e.g., `TB1[...]`) or boundary-to-node connector hacks.
- Attack Flow uses the same classes for consistency.
- Keep external third-party APIs outside core boundaries.
- If a boundary is logically inside another (e.g., template engine inside console), nest subgraphs.

## Code Evidence
- When asserting a flow, point to file paths in the report.
- Avoid claiming CDN or infra behavior without code or runtime evidence.

## Optional Runtime Checks
- Only perform direct URL checks when explicitly requested.
- Record results and incorporate into DFD as “runtime confirmed”.

## Presentation Review (Reader Perspective)
- Before finalizing, review the document from a reader’s perspective and reformat for clarity and flow.
