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

### 3) DFD + Trust Boundaries
- Build a DFD that reflects actual code paths.
- Use explicit trust boundaries. Prefer nesting internal boundaries inside external ones.
- Distinguish internal services, external clients, and third-party APIs.
- Keep node labels concise and stable.
- Keep batch/indexing boundaries separate from logging/messaging unless code shows a direct control or runtime coupling.
- If the DFD feels too flat, add a minimal set of core process nodes (e.g., OrderProc, CouponProc, ManualProc, BatchProc) to clarify data flow between entry points and data stores without over-complicating the diagram.
- Apply a consistent inclusion filter when expanding DFD scope: include modules that handle state-changing operations, external integrations, authentication/authorization boundaries, batch/automation paths, or sensitive data handling. Avoid ad-hoc omissions.

### 4) Attack Flow Overlay
- Create an Attack Flow diagram based on known vulnerabilities or plausible abuse paths.
- Show attacker → exploit → control impact paths.
- Keep it separate from DFD but aligned to DFD nodes.

### 4.1) Attack Scenarios
- Add an Attack Scenarios section after the Attack Flow diagram.
- For each scenario, map confirmed vulnerabilities to IDs when available.
- For uncertain scenarios, list the evidence or questions required to confirm.
- For each scenario, include both: (1) DFD-based normal flow and (2) Attack Flow-based abuse path.
- Prefer a scenario table with columns that capture flow, impact, and confirmation needs.

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

### 7) High-Risk Analysis (Code-Based)
- For top-priority scenarios, add a short code-based analysis section:
  - Code evidence (file paths)
  - Risk summary
  - Confirmation needs (evidence/interview)
  - Architecture-level mitigations

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

## Completion Criteria (General)
Use these as the default “stop” conditions unless the user specifies otherwise:
1. All externally exposed functions (HTTP/API/console/batch/messaging) are identified.
2. For each function, inputs → processing → outputs are confirmed with code evidence.
3. Function-level data stores and external integrations are reflected in the DFD.
4. Attack Flow includes confirmed vulnerabilities and at least one plausible abuse path per major boundary.
5. Anything without code evidence is explicitly marked “not confirmed in code”.
6. Attack Scenarios table is complete for the major systems in scope.

## Diagram Conventions
- DFD uses `trusted`, `untrusted`, `boundary`, `neutral` classes.
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
