# Discovery Process Reference

Use this sequence for external software analysis when source code is missing or incomplete.

1. Artifact triage
- Identify package type (`jar`, `aar`, `so`, `exe`, container layer, etc.).
- Record hashes and version/build strings.

2. Decompilation and extraction
- Decompile/disassemble artifacts with at least two views when possible.
- Preserve original paths and generated output locations.

3. Static candidate collection
- Run pattern scanning (SAST/signature rules, string/symbol search).
- Keep raw hits, then create a narrowed candidate list with reasons.

4. Data/control flow tracing
- Trace source -> sink and boundary transitions.
- Prioritize paths that cross trust boundaries or process sensitive data.

5. Cross-component validation
- If claim depends on integration, trace caller/callee chains across related repos/services.
- Mark each hop as confirmed or not confirmed in code.

6. Evidence packaging
- For each finding, store:
  - artifact path and code location
  - exploit condition summary
  - control assumptions
  - confidence/provenance tag (`binary-confirmed`, `source-confirmed`, `runtime-confirmed`, `not-confirmed`)

7. Reporting handoff
- Write main markdown report.
- Create architecture handoff markdown when boundaries/flows are impacted.
- Emit reporting summary JSON.
