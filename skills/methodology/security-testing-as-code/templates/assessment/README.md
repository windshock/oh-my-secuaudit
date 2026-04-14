# {{Project Name}} Security Assessment

**Engagement ID**: {{ID}}
**Assessor**: {{Name}}
**Date**: {{Start date}} — {{End date}}
**Status**: in-progress | complete | handed-off

## Scope

{{Brief description of what is being assessed and why.}}

- **Target**: {{repo URL / system name / endpoint}}
- **Type**: static | runtime | external | blended
- **Prior assessment**: {{link to prior-assessments/ or "first assessment"}}

## How to Reproduce Findings

### Prerequisites

- {{Tool 1}} (version)
- {{Tool 2}} (version)
- Access to {{environment/system}}

### Quick Start

```bash
# Clone and enter the assessment project
git clone {{this-repo}}
cd assessment

# Run all PoCs
for poc in artifacts/poc/*/; do
  echo "=== $(basename $poc) ==="
  cat "$poc/README.md"
done
```

## Finding Summary

| ID | Title | Severity | Status | PoC |
|---|---|---|---|---|
| FINDING-001 | {{title}} | {{severity}} | confirmed | [link](artifacts/poc/FINDING-001/) |

## Progress

- [ ] Attack surface inventory
- [ ] Static analysis
- [ ] Runtime probing
- [ ] PoC development
- [ ] Report generation
- [ ] Handoff plan
