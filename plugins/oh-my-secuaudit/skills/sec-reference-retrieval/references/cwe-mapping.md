# Category → CWE Mapping

Maps a finding `category` string (the value emitted by producer skills in the `category` field of `finding_schema.json`) to the primary CWE and any related CWEs that should be cross-referenced in Phase 2 retrieval.

The mapping is intentionally minimal in slice 1. Adding a category is a separate PR — see issue [#7](https://github.com/windshock/oh-my-secuaudit/issues/7) follow-ups.

## Mapping Table (Slice 1)

| Category | Primary CWE | Related CWEs | Notes |
|---|---|---|---|
| `SSRF` | CWE-918 (Server-Side Request Forgery) | CWE-601 (Open Redirect); CWE-441 (Unintended Proxy or Intermediary 'Confused Deputy') | Related CWEs often co-occur — redirect-chain SSRF (Next.js / GHE notebook precedents) implicates CWE-601; proxy bypass (Axios NO_PROXY precedent) implicates CWE-441 |

## Pending (Slice 2+)

The following categories appear in producer schemas but are not yet mapped:

| Category | Tentative Primary CWE | Status |
|---|---|---|
| `XSS` | CWE-79 | Slice 2 candidate |
| `SQL Injection` | CWE-89 | Slice 2 candidate |
| `File Upload` | CWE-434 | Slice 2 candidate |
| `Deserialization` | CWE-502 | Slice 2 candidate |
| `Auth Bypass` | CWE-287 | Slice 2 candidate |
| `Command Injection` | CWE-78 | Slice 2 candidate |

When extending: each new category PR must verify that the chosen primary CWE has sufficient GHSA + OWASP CSS coverage to produce a useful ledger row. Categories without external reference coverage are tagged `not-suitable-for-ledger` instead.

## Lookup Logic (used by Phase 1 of SKILL.md)

1. Match the input `category` case-insensitively against the table
2. If found: return `{primary, related[]}`
3. If not found: stop the run with status `category-not-supported`

The skill does NOT fuzzy-match category strings to entries — producer skills must emit categories using the canonical names in this table.
