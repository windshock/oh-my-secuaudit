# Severity Criteria Detail

Use this detail table when converting technical findings into final severity.

## Grade 5 (Critical)
- Remote or near-remote compromise without meaningful preconditions.
- Authentication bypass leading to privileged control.
- Cryptographic trust collapse enabling account takeover at scale.

## Grade 4 (High)
- High-impact exploit requiring realistic but non-trivial preconditions.
- Boundary break across service tiers (for example, internal API trust abuse).
- Exposure of high-value secrets enabling follow-on critical impact.

## Grade 3 (Medium)
- Exploit requires stronger assumptions (local access, narrow context, or partial controls).
- Business-impacting integrity or confidentiality issue with constrained blast radius.

## Grade 2 (Low)
- Weakness is real but difficult to operationalize in expected environments.
- Hardening gap with limited direct exploitability.

## Grade 1 (Info)
- Observation, anti-pattern, or quality issue without demonstrated security impact.

## Adjustment Rules
- Increase one level if exploit chain composes cleanly with another confirmed finding.
- Decrease one level if a confirmed, always-on control blocks practical abuse.
- Keep rationale explicit in the report for every adjusted severity.
