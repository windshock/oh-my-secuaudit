# Handoff Plan

**Assessment**: {{Project name}}
**Assessor**: {{Name}}
**Date**: {{Date}}
**Status**: {{complete|partial|handed-off}}

## 1. Completed Scope

| Area | Coverage | Findings | Evidence |
|---|---|---|---|
| {{Area 1}} | Full/Partial | N findings | `artifacts/poc/FINDING-*` |
| {{Area 2}} | Full/Partial | N findings | `artifacts/runtime/...` |

## 2. Open Gaps

### 2.1 Not Tested (Time Constraints)
- {{Area/component}} — Reason: ran out of engagement window
  - **Recommended priority**: High/Medium/Low
  - **Estimated effort**: {{hours/days}}

### 2.2 Not Tested (Access Limitations)
- {{Area/component}} — Reason: no access to {{system/environment}}
  - **What access is needed**: {{description}}
  - **Who to contact**: {{role/team, not individual names}}

### 2.3 Not Tested (Environment Unavailable)
- {{Area/component}} — Reason: {{environment}} was down/unavailable
  - **When to retry**: {{condition or date}}

## 3. Recommended Next Steps (Priority Order)

1. **[High]** {{Action}} — because {{risk justification}}
2. **[Medium]** {{Action}} — because {{risk justification}}
3. **[Low]** {{Action}} — because {{risk justification}}

## 4. Environment Setup

```bash
# How to set up the test environment for the next assessor
{{commands or reference to setup docs}}
```

### Required Access
- {{System}}: {{role/permission needed}} (request from {{team}})
- {{System}}: {{role/permission needed}}

**Note**: Never store actual credentials here. Reference the credential store or access management system.

## 5. Known False Positive Patterns

Save the next assessor from re-investigating these:

| Pattern | Why It's Not a Finding |
|---|---|
| {{Tool/rule}} flagging {{code pattern}} | {{Explanation: why it's safe in this context}} |

## 6. Key Contacts

| Role | Team | Context |
|---|---|---|
| {{Role}} | {{Team name}} | {{What they can help with}} |

## 7. Assessment Timeline

| Date | Milestone |
|---|---|
| {{Date}} | Engagement start |
| {{Date}} | {{Key event}} |
| {{Date}} | Handoff |
