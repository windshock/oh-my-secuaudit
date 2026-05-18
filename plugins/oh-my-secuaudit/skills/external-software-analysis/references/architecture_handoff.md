# External Analysis -> Architecture Handoff Template

Use this template to pass binary/package findings to `security-architecture-review`.

## Handoff Metadata
- Analysis date:
- Target component:
- Artifact path(s):
- Version/build:
- Analyst confidence:

## Integration Map
| Component | Inbound caller | Outbound target | Interface (API/function/protocol) | Evidence |
|---|---|---|---|---|
| | | | | |

## Boundary and Flow Impact
| finding_id | Impacted trust boundary | Normal flow (DFD) | Abuse path (Attack Flow) | Impact summary |
|---|---|---|---|---|
| | | | | |

## Data Exposure/Manipulation Points
| Path/Function | Input source | Output sink | Sensitive fields | Validation/Control | Evidence |
|---|---|---|---|---|---|
| | | | | | |

## Evidence Provenance
Tag each claim with one:
- `binary-confirmed`
- `source-confirmed`
- `runtime-confirmed`
- `not-confirmed`

## Open Questions for Architecture Review
- What must be confirmed in source/infrastructure?
- Which assumptions could change risk severity?
