# Ledger Row Template

Use this template to compose Phase 4 output. The result is a single markdown row appended to `security-field-notes/knowledge/appsec/synthesis-ledger.md` via PR.

This template is calibrated against the `synthesis-ledger.md` at commit `45d22ab` (2026-05-21). If the upstream ledger schema changes, update this template.

## Schema (8 columns, in order)

```markdown
| Date | Finding pattern | CWE(s) | Sources matched | Evidence refs | Synthesis | Used in | Last verified |
```

## Column Specifications

| # | Column | Format | Notes |
|---|---|---|---|
| 1 | `Date` | `YYYY-MM-DD` | Today's date when the row is composed |
| 2 | `Finding pattern` | Short noun phrase | Scrubbed of internal identifiers; describes the vulnerability class, not the specific finding |
| 3 | `CWE(s)` | `CWE-NNN; CWE-NNN (description)` | Primary CWE first; related CWEs with parenthetical description |
| 4 | `Sources matched` | Semicolon-separated list of source names; misses recorded explicitly | E.g., `GitHub Advisory; AppSec.fyi #1, #2, #3, #9` or `GitHub Advisory; (AppSec.fyi 직접 hit 없음)` |
| 5 | `Evidence refs` | Semicolon-separated tokens | Per `references/source-catalog.md` format. E.g., `GHSA-c4j6-fc7j-m34r; commit:c4f69086; CWE-918` |
| 6 | `Synthesis` | ≤3 dense sentences | Must contain: GHSA id, commit short sha, version range, CVSS, fix mechanism. Every claim backed by an Evidence-refs token. |
| 7 | `Used in` | Free-form short phrase | E.g., `retrieval test (sec-reference-retrieval PoC slice 1)` |
| 8 | `Last verified` | `YYYY-MM-DD` | Today's date (same as Date) on first write. Stale threshold: 90 days (advisory sources shorter, taxonomy sources longer) |

## Calibration Examples (from existing backfill rows)

Read these to anchor synthesis quality:

```markdown
| 2026-05-21 | Self-hosted Next.js WebSocket upgrade SSRF | CWE-918 | GitHub Advisory; AppSec.fyi #1, #2, #3, #9 | GHSA-c4j6-fc7j-m34r; commit:c4f69086; CWE-918 | upgrade handler가 정상 HTTP handler에 있는 routing-completion gate(`finished && parsedUrl.protocol && !statusCode`)를 누락. fix: 동일 gate를 upgrade handler에도 추가. Affected ≥13.4.13, <15.5.16 + ≥16.0.0, <16.2.5. CVSS 8.6 | retrieval test (3 SSRF CVE walkthrough) | 2026-05-21 |
| 2026-05-21 | Axios NO_PROXY hostname normalization bypass | CWE-918; CWE-441 (Unintended Proxy) | GitHub Advisory; (AppSec.fyi 직접 hit 없음) | GHSA-3p68-rc4w-qgx5; commit:fb3befb6; CWE-918; CWE-441 | NO_PROXY 비교 시 hostname 정규화 부재 → `localhost.`(trailing dot), `[::1]`(IPv6 brackets) 우회. fix: `shouldBypassProxy()` helper에서 trailing dot 제거 + IPv6 brackets strip 후 NO_PROXY 비교. Affected ≥1.0.0, <1.15.0 + <0.31.0. CVSS 6.3 | retrieval test (multi-source CWE+GHSA가 AppSec.fyi 사각지대 메움) | 2026-05-21 |
| 2026-05-21 | GitHub Enterprise notebook rendering SSRF via unrevalidated redirect | CWE-918; CWE-601 (Open Redirect) | vendor advisory (SentinelOne writeup); (AppSec.fyi에 직접 5921 없음, 관련 GHE 2026-8034 언급) | vendor-advisory-only; CWE-918; CWE-601 | notebook viewer가 HTTP redirect의 destination host를 재검증 없이 따라감 → unauthenticated SSRF + timing side-channel로 환경변수 추출. Mitigation: enable private mode. Patched: 3.14.26 / 3.15.21 / 3.16.17 / 3.17.14 / 3.18.8 / 3.19.5 / 3.20.1 | retrieval test (proprietary 제품 — multi-source 한계: vendor 외 직접 source 없음) | 2026-05-21 |
```

Observe:

- `Sources matched` records misses explicitly (`AppSec.fyi 직접 hit 없음`); does not silently omit
- `Evidence refs` is token-only (no prose); semicolon-separated
- `Synthesis` mixes Korean and English where the upstream source language varies; this is allowed
- `Used in` ties the row to a specific session/context for §14 audit trail

## Scrub Checklist

Run before opening PR-B. Reject the row if any of the following appears anywhere in the row or PR body:

- [ ] Internal hostnames (e.g., `*.internal`, `*.corp`, IP ranges 10/8, 172.16/12, 192.168/16)
- [ ] Employee names or @-handles
- [ ] Ticket / Jira / internal issue IDs (e.g., `SEC-1234`, `INTERNAL-XXXX`)
- [ ] Internal repository paths (e.g., `git@internal:...`, anything not on `github.com/<public-owner>/...`)
- [ ] Local filesystem paths from the assessor's machine (`/Users/...`, `/home/...`, `C:\Users\...`)
- [ ] Credentials, tokens, or secrets in any form

If the source `evidence_summary` contains any of these, redact in synthesis. The PR-B reviewer is the §14 governance gate and the second check.
