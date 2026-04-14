# Security Assessment Code Clustering Strategy v4

## 1. Core Principle

> A cluster does not guarantee identical results. A cluster provides the possibility of applying the same review strategy.

The operating procedure — verifying clusters while using them — is the core of this strategy, not the clustering itself.

## 2. Background

Modern applications contain repetitive security patterns. Reviewing each individually causes:
- Increased manual review time
- Duplicate analysis of identical patterns
- Quality variance across reviewers

Goal: Group similar security-relevant code paths by cluster, enabling representative-sample review to reduce cost and improve consistency.

## 3. Scope

### 3.1 Include (requires dataflow analysis)

| Check Item | Reason |
|---|---|
| XSS | Sink context (HTML, JS, attribute) determines vulnerability |
| Data protection | Masking/encryption/exposure varies by flow |
| SSRF / path traversal / template injection | Input propagation path analysis required |
| Auth/authz (conditional) | Per-endpoint authorization varies |

### 3.2 Exclude (static pattern matching sufficient)

- Detectable by single grep/Semgrep/SAST rule
- Uniformly handled by common module
- Single-rule decidable

### 3.3 Auth/Authz Re-definition

Auth is not "does a common module exist" but "is the module correctly invoked per-endpoint":
- Per-endpoint `@PreAuthorize`/`@Secured` application varies
- Security filter bypass possibility exists
- Auth flow branches conditionally

> Auth is a "per-path application verification" problem, not a "module verification" problem.

## 4. Clustering Unit

**(Endpoint, Sink) source-to-sink dataflow path**

Rationale:
- One endpoint may have multiple sinks → endpoint-only boundary is unclear
- Same sink reused across endpoints → sink-only grouping ignores security context differences
- Vulnerability depends on the path to sink → (endpoint, sink) is the minimal analysis unit

## 5. Methodology

### 5.1 Feature Definition

| Element | Description | Example |
|---|---|---|
| Source | User input, external data entry | HTTP param, DB result |
| Transformation | Processing logic | String ops, parsing |
| Validation/Sanitization | Filtering, encoding | HTML encode, SQL escape |
| Sink | Final output point | HTML output, query execution |
| Context | Auth state, data sensitivity | Auth state, PII flag |

### 5.2 Representation

- Primary: Graph representation (dataflow-based)
- Secondary: Vector (TF-IDF) when graph construction is infeasible

### 5.3 Algorithms

| Type | Algorithm | When |
|---|---|---|
| Graph-based | Leiden, Louvain | Dataflow graph available |
| Vector-based | K-means | TF-IDF vector representation |
| Hybrid | Graph embedding + K-means | Mixed graph + code pattern |

## 6. Execution Pipeline

| Step | Action | Tools |
|---|---|---|
| Step 1 | Candidate filtering: remove simple patterns, pre-process clear cases | Semgrep, grep, SAST |
| Step 2 | Dataflow extraction (priority: Fortify+fortify_ml > Semgrep taint > CodeQL/Joern > Custom AST+callgraph+taint) | fortify_ml, CodeQL, Joern, tree-sitter |
| Step 3 | Clustering: group by dataflow path, reflect sink-centric similarity | Leiden, K-means |
| Step 4 | Representative sample selection (priority: high-risk sink > unclear sanitizer > path complexity) | — |
| Step 5 | Cluster verification: min 2 samples per cluster manual review; split or exclude on problems | Manual review |
| Step 6 | Apply results: extend representative findings to cluster; manage exceptions separately | — |

## 7. Evaluation

### 7.1 Intra-cluster Consistency
- Definition: Same-verdict rate within a cluster
- Formula: (matching samples) / (reviewed samples)
- Sampling: <10 cluster size = exhaustive; >=10 = 30% or min 3

### 7.2 Review Efficiency
- Formula: savings = 1 - (clustered time) / (unclustered time)

### 7.3 Sample Miss Rate
- Formula: (mismatched samples) / (additional samples)
- High miss rate → signal to split cluster

### 7.4 Reviewer Agreement
- Cohen's Kappa or simple agreement (>=2 reviewers)
- Low Kappa = review criteria misalignment, not necessarily cluster quality issue

### 7.5 Bootstrapping Stages

| Stage | Criteria | Action |
|---|---|---|
| Stage 1 (initial) | New cluster | 50%+ manual review, measure consistency |
| Stage 2 (stabilization) | Consistency >= 80% | Reduce to 30% sampling |
| Stage 3 (operational) | Miss rate < 5% for 2 consecutive cycles | Representative sample review only |
| Re-verification | Major code change / new framework / missed vuln | Reset to Stage 1 |

## 8. Failure Conditions

| Condition | Reason |
|---|---|
| Reflection / dynamic dispatch | Static analysis cannot trace actual flow |
| AOP / proxy-based flow | Runtime-determined security processing |
| Framework internal hidden flow | Dataflow breaks inside framework |
| Runtime config-dependent sanitizer | Same code, different behavior by config |
| Template engine internals | Cannot trace escaping |

### 8.1 Fallback

1. **Tag** failed paths during Step 1
2. **Separate** from clustering pipeline into standalone list
3. **Prioritize**: external input paths > auth bypass paths > rest
4. **Review** manually with checklist for consistency
5. **Document** in separate report section

## 9. Tool Strategy

| Role | Tool | Purpose |
|---|---|---|
| Primary | fortify_ml | Fortify scan-based dataflow clustering |
| Alternative | Semgrep (taint) | Non-Fortify environments |
| Alternative | CodeQL / Joern | Deep dataflow analysis |
| Supporting | graphify | Code structure analysis, critical node detection |
| Supporting | understand-anything | Domain/architecture-level grouping |

## 10. Conclusion

> The essence: cluster security-meaningful flows, not code.

Achieved:
- N individual implementations → K clusters (K << N)
- Representative-sample review improves efficiency
- Consistent review strategy per cluster

Without cluster verification (Step 5) and metrics operation (Section 7), this strategy's reliability is not guaranteed.
