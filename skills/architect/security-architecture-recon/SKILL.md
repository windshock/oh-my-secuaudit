---
name: security-architecture-recon
description: Reconstruct security architecture from a codebase by producing an attack surface inventory, DFD-style data flows, sensitive data map, trust boundaries, risk summary, and SAST rule candidates. Use when asked to derive architecture or security design/requirements from code, scope a security assessment, or translate code into security-focused documentation.
---

# Security Architecture Recon

## Overview

Rebuild security architecture and design artifacts directly from code. Focus on externally reachable entry points, sensitive data flows, trust boundaries, and security controls, then summarize risks and derive repeatable SAST patterns.

## Workflow

### 1. Set Scope And Dependencies

1. Confirm target module(s) and expand scope only as needed (target → related modules → whole repo).
2. Identify build system and dependencies (e.g., `pom.xml`, Gradle, package manifests).
3. If source code for a required module is missing, decompile only the specific proprietary or internal artifacts that are directly used by the target scope (e.g., TID). Do not decompile unrelated modules or open-source dependencies.
4. If an `AGENTS.md` exists in the repo, follow its instructions for scanning and reporting.

### 2. Build Attack Surface Inventory

Create a concise list of entry points and exposure types:

1. HTTP endpoints (controllers, routes, RPC handlers).
2. Message consumers, cron jobs, batch processors, file ingest.
3. Admin and operational endpoints.
4. External integrations (HTTP clients, SDKs, DBs, queues, storage).

Recommended output columns:
- `Entry` (route/topic/job)
- `Method/Type`
- `Auth/Role`
- `Inputs`
- `Outputs`
- `Notes`

### 3. Draft DFD And Sensitive Data Map

1. Identify sources: request params, headers, body, files, tokens, queue messages.
2. Track transformations: validators, mappers, DTO builders, encryption/hashing.
3. Identify sinks: DB writes, external API calls, caches, logs, file writes.
4. Note sensitive fields: session IDs, tokens, PII, credentials.

Provide:
- A simple DFD list: nodes and edges (source → processor → sink).
- A sensitive data table: field → where created → where used → where stored/transmitted.

### 4. Identify Trust Boundaries And Controls

1. Mark external boundary: user/client to server.
2. Mark internal boundaries: service-to-service, module-to-module, network tiers.
3. Locate controls: authn/authz, input validation, rate limiting, crypto, logging, audit.

### 5. Summarize Risks

1. Map missing or weak controls to entry points or flows.
2. Prioritize by exposure and sensitivity.
3. Include specific code locations or patterns when possible.

### 6. Derive SAST Rule Candidates

1. Convert repeated risky patterns into AST or taint rules.
2. Start with minimal patterns and tighten as needed.
3. Use Semgrep and Joern for SAST. Prefer Semgrep for quick pattern/taint rules and Joern for deep data-flow and inter-procedural queries.
4. Run small-scope scans first; expand scope after validation.
5. If an `AGENTS.md` loop exists, follow it without asking for extra input.

## Output Template

Use a flexible structure. If no format is specified, default to:

1. Scope and dependencies
2. Attack surface inventory
3. DFD summary
4. Sensitive data map
5. Trust boundaries and controls
6. Risk summary
7. SAST rule candidates and scan notes

Keep lists flat and concise. Include file references when making code-specific claims.
