# External Software Analysis Report Template

## Report Metadata
- Date:
- Target:
- Scope:
- Artifact(s):
- Analysis basis: static / runtime / mixed

## 1. Scope and Assumptions
- What is in/out of scope
- Trust assumptions
- Unknowns marked as `not-confirmed`

## 2. Discovery Summary
- Tools used
- Candidate counts and narrowing decisions
- Final finding set

## 3. Attack Surface (External Component Perspective)
| Interface | Input | Security control | Notes | Evidence |
|---|---|---|---|---|
| | | | | |

## 4. Findings
For each finding:
- Finding ID:
- Severity:
- Confidence/provenance:
- Impact:
- Conditions:
- Evidence:
- Mitigation:

## 5. Flow and Boundary Impact
| finding_id | Affected boundary | Normal flow | Abuse path | Confirmation needs |
|---|---|---|---|---|
| | | | | |

## 6. Integration Chain (if applicable)
- Chain notation: `Client -> Service A -> Service B -> External Component`
- Mark each hop as `confirmed in code` or `not confirmed in code`.

## 7. Safe-Sharing Notes
- Sensitive values to redact
- Internal endpoints or identifiers requiring masking

## 8. Output Artifacts
- Main report path
- Architecture handoff path (if produced)
- Summary JSON path
