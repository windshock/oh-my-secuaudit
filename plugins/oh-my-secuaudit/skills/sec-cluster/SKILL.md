---
name: sec-cluster
description: Dataflow-based code clustering for security assessments. Groups (Endpoint, Sink) paths by shared review strategy so reviewers sample representative cases instead of exhaustively reviewing every path. Use when scoping manual review on a codebase with 50+ endpoints, repetitive sanitization patterns, or after initial SAST/SCA produces large finding sets that need triage.
---

# sec-cluster: Security Code Clustering

Dataflow-based code clustering for security assessments. Groups (Endpoint, Sink) paths by shared review strategy, enabling representative-sample review instead of exhaustive per-path analysis.

## Core Principle

> A cluster does not guarantee identical results. A cluster provides the possibility of applying the same review strategy.

Therefore the operating procedure is: **verify clusters while using them**, not trust them blindly.

## When to Use

- Codebase has 50+ endpoints with repetitive security patterns
- Multiple modules share similar sanitization/validation gaps
- Need to scope a manual review efficiently after initial SAST/SCA
- Architecture review requests cluster-to-scenario mapping

## Inputs

- Source repository (buildable preferred)
- Existing `sec-audit-static` findings (optional, accelerates Phase 1)
- Architecture review scenarios (optional, for cross-reference)

## Workflow

### Phase 0: Read References

1. Read `references/clustering_strategy_v4.md` for the full strategy.
2. Review `templates/` for output format examples.

### Phase 1: Scope and Exclusion

Determine clustering applicability per the v4 strategy:

**Include** (requires dataflow analysis):
| Check Item | Clustering Reason |
|---|---|
| XSS | Sink context (HTML, JS, attribute) determines vulnerability |
| Data protection | Masking/encryption/exposure varies by flow |
| SSRF / path traversal / template injection | Input propagation path analysis required |
| Auth/authz (conditional) | Per-endpoint authorization application differs (v4 section 3.3) |

**Exclude** (static pattern matching sufficient):
- Single-rule detectable patterns (e.g., `Runtime.exec`, `ProcessBuilder`)
- Uniformly handled by a common module
- Batch/cron paths without inbound HTTP endpoints
- Hardcoded secrets/keys (Gitleaks/Semgrep regex)

**Auth/Authz Re-definition** (v4 section 3.3):
> Auth is not "does a common module exist" but "is it applied per-endpoint." Include in clustering when endpoint-level authorization varies.

### Phase 2: Automated Detection (Semgrep Sweep)

1. Adapt semgrep rule templates from `templates/semgrep-rules/` to the target codebase:
   - Replace project-specific identifiers with target-appropriate patterns
   - Adjust `metavariable-regex` for domain-specific field names
   - Add/remove rules based on Phase 1 scope decisions
2. Run sweep using `templates/sweep.sh` (adapt module list):
   ```bash
   ./sweep.sh              # all modules, human output
   ./sweep.sh --json       # JSON output
   ./sweep.sh <module>     # single module
   ```
3. Record match counts per cluster per module.

### Phase 3: Endpoint Enumeration (C1 Auth Cluster)

For the auth/authz cluster (typically the largest):

1. Enumerate all `@RequestMapping`/`@GetMapping`/`@PostMapping` endpoints
2. For each controller, check:
   - `@PreAuthorize`, `@Secured`, `SecurityFilterChain` presence
   - `WebConfig`/`addInterceptors()` auth interceptor registration
   - Service-layer signature/HMAC/token verification
3. Record: module, controller, endpoint count, auth mechanism (or "none")
4. Use `templates/auth_enum.sh` as a starting point (adapt grep patterns).

### Phase 4: Cluster Definition

Define clusters using the (Endpoint, Sink) unit. For each cluster, document:

| Element | Description |
|---|---|
| Source | User input / external data entry point |
| Transformation | Processing logic |
| Validation/Sanitization | Filtering, encoding presence |
| Sink | Final output point (DB, HTTP response, file, external call) |
| Context | Auth state, data sensitivity, trust boundary |

Typical cluster categories:
- **C1**: Endpoint-level auth/authz gaps (conditional)
- **C2**: Hardcoded shared-secret / manual-processing patterns
- **C3**: SSL/Hostname verification bypass (unsafe consumption)
- **C4**: Sensitive data logging (identifiers, credentials, full request/response)
- **C5**: Unsafe deserialization (XML/XStream/XXE without hardening)

Adjust cluster definitions to the target codebase. Not all categories apply to every project.

### Phase 5: Representative Sample Review (Bootstrapping)

Per v4 section 7.5:

| Stage | Criteria | Sampling |
|---|---|---|
| Stage 1 (initial) | New cluster | 50%+ manual review, measure consistency |
| Stage 2 (stabilization) | Consistency >= 80% | Reduce to 30% sampling |
| Stage 3 (operational) | Miss rate < 5% for 2 consecutive cycles | Representative sample only |
| Re-verification trigger | Major code change, new framework, missed vuln | Reset to Stage 1 |

For each sample, fill the review checklist (see `templates/REVIEW_CHECKLIST.md.tmpl`):
- Check auth mechanisms, sanitizers, sink protections
- Mark `[X]` (vulnerable), `[N]` (not vulnerable), or `[partial]`
- Record cross-cluster interactions (e.g., C1 x C5 = auth gap + deserialization)

### Phase 6: Output Generation

Produce these artifacts in the target's `architecture-review/` or assessment output directory:

1. **`CLUSTERS.md`** — Full cluster inventory with:
   - Scope and exclusions
   - Per-cluster definition (feature table, endpoint-sink enumeration, representative samples)
   - Phase 2 match counts (actual vs. estimated)
   - Cross-cluster interaction matrix
   - Off-scope findings discovered during clustering
   - Bootstrapping guide with consistency metrics

2. **`semgrep-rules/`** — Adapted rules with `results/SUMMARY.md`

3. **`semgrep-rules/results/REVIEW_CHECKLIST.md`** — Completed review with:
   - Per-sample verdicts
   - Consistency rate per cluster
   - Bootstrapping stage judgment

## Failure Conditions

Clustering is ineffective when:
| Condition | Reason |
|---|---|
| Reflection / dynamic dispatch | Static analysis cannot trace actual flow |
| AOP / proxy-based flow | Runtime-determined security processing |
| Framework internal hidden flow | Dataflow breaks inside framework |
| Runtime config-dependent sanitizer | Same code, different behavior by config |
| Template engine internal processing | Cannot trace internal escaping |

**Fallback**: Tag failed paths in Phase 1, manage separately, review manually prioritized by: external input proximity > auth bypass potential > rest.

## Outputs

| Artifact | Description | Consumed By |
|---|---|---|
| `CLUSTERS.md` | Cluster definitions, measurements, cross-references | `sec-audit-static`, `security-architecture-review` |
| `semgrep-rules/*.yaml` | Codebase-adapted detection rules | `sec-audit-static` re-runs |
| `semgrep-rules/results/SUMMARY.md` | Detection statistics | `CLUSTERS.md`, architecture review |
| `semgrep-rules/results/REVIEW_CHECKLIST.md` | Sample review verdicts and consistency | Architecture review, next audit cycle |

## Handoff to Architecture Review

Provide:
- Cluster-to-scenario mapping (e.g., C1 -> S1,S2,S4)
- Cross-cluster attack chains (e.g., C1 x C5 = auth gap + unsafe deserialization)
- Consistency metrics per cluster (bootstrapping stage)
- Off-scope findings with severity assessment

## Evaluation Metrics (v4 Section 7)

| Metric | Definition | Formula |
|---|---|---|
| Intra-cluster consistency | Same-verdict rate within cluster | (matching samples) / (reviewed samples) |
| Review efficiency | Time saved vs. exhaustive review | 1 - (clustered time) / (unclustered time) |
| Sample miss rate | Vulnerabilities missed by representative sampling | (mismatched samples) / (additional samples) |
| Reviewer agreement | Cross-reviewer verdict consistency | Cohen's Kappa or simple agreement rate |

## Resources

- `references/clustering_strategy_v4.md` — Full v4 strategy document
- `templates/semgrep-rules/` — Starter rule templates (5 categories)
- `templates/sweep.sh` — Module sweep runner
- `templates/auth_enum.sh` — Auth mechanism enumeration helper
- `templates/CLUSTERS.md.tmpl` — Cluster document template
- `templates/REVIEW_CHECKLIST.md.tmpl` — Review checklist template

## Related Reading

- [Structure Builders Will Outlast Vulnerability Finders](https://windshock.github.io/en/post/2026-04-02-security-from-sense-to-structure/) — Systematic structure over ad-hoc finding
