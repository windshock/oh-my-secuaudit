---
name: sec-reference-retrieval
description: Query multi-source AppSec catalogs (CWE / OWASP Cheat Sheet Series / GitHub Advisory Database / AppSec.fyi) for a given security finding and propose a synthesis row to the security-field-notes synthesis-ledger via PR. Use when a producer skill (sec-audit-static, sec-audit-dast, external-software-analysis) emits a finding that needs external reference enrichment, or when packaging an assessment finding for downstream remediation context.
---

# sec-reference-retrieval: Multi-Source AppSec Reference Retrieval

Given a security finding (typically from a producer skill), query four upstream AppSec catalogs in parallel, distill the matches into a single dense synthesis, and propose a row to the `security-field-notes` synthesis ledger via PR. The skill is the pull-side counterpart to the push-side workflow in `security-architecture-review` — it brings external context IN, while SAR pushes findings OUT to remediation.

## Core Thesis

> A finding without external reference is a hypothesis. A finding with reconciled multi-source synthesis is a contract surface.

The skill does not produce knowledge of its own — it retrieves what already exists (CWE / OWASP / GHSA / AppSec.fyi), distills it into a reusable row, and submits it through the §14 PR-reviewed staging layer so future LLMs can read the row instead of re-running the same retrieval.

## PoC Scope (Slice 1 + 2)

This skill is being built in narrow slices. Current covered:

- **Categories**: `SSRF` (slice 1) + `XSS` (slice 2). Other categories deferred to slice 3+.
- **Manual phase execution** — Claude follows the 4-phase playbook manually; no orchestration code (slice 3+).
- **One ledger row per run** — no batching.
- **PR-based write-back** — `security-field-notes` updates are human-opened PRs (auto-PR is slice 3+, intentionally delayed until ledger row shape stabilizes across multiple categories).
- **No caching** — no Filesystem MCP, no vector store, no semantic cache. Each Phase 2 fetch is fresh.
- **Stale guard: documented + drill, not enforced** — the rule + checklist is in this SKILL.md and `templates/ledger-row.md`; the dry-run output for each new row explicitly records its stale-check verdict against prior ledger rows. Automated enforcement is deferred (slice 3+).

Tracking: issue [#7](https://github.com/windshock/oh-my-secuaudit/issues/7).

## When to Use

- After a producer skill (`sec-audit-static`, `sec-audit-dast`, `external-software-analysis`) emits a finding whose `category` matches an entry in `references/cwe-mapping.md`
- When packaging an assessment finding via `security-testing-as-code` and external reference context is needed for the PoC narrative
- When a `security-architecture-review` synthesizer needs reconciled external context for an attack scenario (manual invocation)

## Inputs

- `category` — the finding's category string (e.g., `"SSRF"`, `"XSS"`, `"deserialization"`). Slices 1+2 support `SSRF` and `XSS`.
- `evidence_summary` — short text describing the candidate (e.g., `"Image proxy endpoint follows redirect without validating destination host"`). Used only for synthesis context; never echoed into the ledger row verbatim (scrub guard).

## Outputs

- One 8-column markdown row matching the `security-field-notes/knowledge/appsec/synthesis-ledger.md` schema
- A scrub confirmation note (no internal hostnames / paths / employee names / ticket IDs in row or PR body)
- A draft PR title and body targeting `windshock/security-field-notes`

## 4-Phase Cascading Filter Playbook

### Phase 1: Category → CWE

1. Read `references/cwe-mapping.md`.
2. Locate the row for the input `category`. If not present in slice 1's mapping, stop and report `category-not-supported`.
3. Extract `primary_cwe` (e.g., `CWE-918` for SSRF) and `related_cwes` (e.g., `CWE-601`, `CWE-441`).

### Phase 2: Parallel Fetch

Read `references/source-catalog.md` for per-source fetch verbs. Execute the four fetches in parallel:

1. **GitHub Advisory Database (GHSA)**:

   The GHSA REST endpoint accepts `cwes` as the **numeric CWE ID only** (e.g., `918`, `79`). The `CWE-` prefix MUST be stripped before the API call — `cwes=CWE-918` silently returns zero results (confirmed against the live API 2026-05-22). The skill's representation of CWE elsewhere (Evidence refs, ledger row, SKILL.md prose) keeps the `CWE-NNN` form; only the GHSA query strips the prefix.

   ```
   PRIMARY_CWE_NUM="${PRIMARY_CWE#CWE-}"     # e.g., CWE-918 → 918
   gh api "/advisories?cwes=${PRIMARY_CWE_NUM}&per_page=20&sort=updated"
   ```

   Filter results to advisories with both a patch commit reference and a CVSS score. If the advisory text does not link a patch commit directly, recover it via `gh api /repos/<owner>/<repo>/commits?path=<vulnerable-file>` against the upstream repo (this was the slice-2 NocoDB workflow — the GHSA page didn't link the patch commit). Skip any advisory whose `ghsa_id` already appears in `security-field-notes/knowledge/appsec/synthesis-ledger.md` (check the live file at runtime, not a snapshot).

2. **CWE canonical definition**: `WebFetch https://cwe.mitre.org/data/definitions/<NNN>.html`. Use `primary_cwe` only; related CWEs need not be fetched unless synthesis ambiguity arises.

3. **OWASP Cheat Sheet Series**: `WebFetch` the relevant cheat sheet at the URL specified per category in `source-catalog.md`.

4. **AppSec.fyi**: `WebFetch` the relevant topic page (`https://www.appsec.fyi/<topic>.html`). If the page does not exist or has no relevant content for the candidate, **record the miss explicitly** in the `Sources matched` cell of the row (Axios precedent — see existing ledger row 2026-05-21 Axios NO_PROXY).

If any source rate-limits or returns 5xx, retry once with exponential backoff. If still failing, record the source as `(unavailable at retrieval time)` in `Sources matched` and proceed.

### Phase 2.5: Stale Guard Check (slice 2)

Before composing the new row, perform an explicit stale check against the existing ledger. **The check is documented and run by the assessor; it is NOT yet automated** (automation is deferred to slice 3+).

Procedure:

1. List all existing rows in `synthesis-ledger.md` whose `Finding pattern` or `CWE(s)` is **related to the current candidate**. Two rows are "related" when:
   - Same primary CWE, OR
   - Same vulnerability class (e.g., SSRF + open redirect, XSS + DOM XSS), OR
   - Same affected package family
2. For each related row, classify its `Last verified` date:
   - **Fresh** = within 30 days for advisory-class sources (GHSA / vendor advisories); within 90 days for taxonomy sources (CWE / OWASP CSS); within 90 days for AppSec.fyi (curation)
   - **Stale** = older than the threshold above
3. **Authoritative-use rule** — when composing the new row's `Synthesis`:
   - May reference *fresh* prior rows for context (e.g., "similar to GHE notebook SSRF row 2026-05-21")
   - MUST NOT cite *stale* rows as authoritative — they remain in the ledger as historical staging entries only
4. Record the stale-guard check verdict in the PR-B body under a "Stale Guard check" section. Example: `Stale Guard check: 4 SSRF-family rows examined (Next.js / Axios / GHE / Coder, all Last verified 2026-05-21 — fresh); no stale citations used in this run.`

If there are zero related rows, record `Stale Guard check: no prior related rows in ledger.`

### Phase 3: LLM Merge

Distill the four (or fewer, on misses) source outputs into a single dense synthesis cell that follows the quality bar set by the 3 backfill rows in `synthesis-ledger.md`:

- **Required claims** in the Synthesis cell (≤3 sentences):
  - GHSA ID (full form, e.g., `GHSA-c4j6-fc7j-m34r`)
  - Patch commit short SHA (7 chars, e.g., `c4f69086`)
  - Affected version range (e.g., `≥13.4.13, <15.5.16 + ≥16.0.0, <16.2.5`)
  - CVSS score (e.g., `CVSS 8.6`)
  - Fix mechanism (1 sentence describing what the patch does)
- **Backing rule**: every claim above MUST be backed by a token already present in the Evidence refs cell. Do not introduce information that has no upstream source token.

### Phase 4: Compose Row + Scrub + PR

1. Use `templates/ledger-row.md` to fill all 8 columns:
   - `Date`: today (ISO `YYYY-MM-DD`)
   - `Finding pattern`: short noun phrase describing the vulnerability class (scrubbed of internal identifiers)
   - `CWE(s)`: `primary_cwe`; `related_cwes` if both contribute
   - `Sources matched`: list each source that hit. Misses recorded as `(<Source> 직접 hit 없음)` per Axios precedent
   - `Evidence refs`: GHSA-id; `commit:<short_sha>`; OWASP cheat sheet name; CWE-NNN — semicolon-separated
   - `Synthesis`: the Phase 3 cell
   - `Used in`: `retrieval test (sec-reference-retrieval PoC slice <N>)` where `<N>` is the current slice
   - `Last verified`: today (ISO)

2. **Scrub pass** (LLM-driven in slice 1, PR review is the §14 gate):
   - Reject any internal hostname, employee name, ticket ID, internal repo path, or local file path in the row or PR body
   - If the input `evidence_summary` contains any of the above, redact in the synthesis

3. **Open PR-B** against `windshock/security-field-notes`:
   - Branch: `ledger/<category-lowercase>-<ghsa-short>` (e.g., `ledger/ssrf-c4j6fc7j`)
   - Title: `ledger: add <category-uppercase> retrieval row for <ghsa_id>`
   - Body: links the oh-my-secuaudit PR-A, references issue #7, attaches scrub confirmation, **and includes the Phase 2.5 Stale Guard check verdict**
   - **Do not auto-merge.** PR-B awaits §14 governance review.

## Governance Guards (§14 protocol from security-field-notes/AGENTS.md)

The skill is bound by `security-field-notes/AGENTS.md §14`. These rules govern every run:

1. **Ledger ≠ knowledge endpoint** — the row is a staging entry, not a canonical knowledge page
2. **Reuse threshold** — only `security-field-notes` maintainers graduate rows to `knowledge/appsec/<topic>.md` after ≥3 hits. The skill MAY append a new finding pattern to `## Promotion Status` at `1 hit`, but MUST NOT increment hit counts on existing patterns or trigger graduation (those are human-curated decisions).
3. **Stale rows non-authoritative** — when synthesizing, the skill MUST NOT cite a stale ledger row as authoritative. Thresholds: **30 days** for advisory-class sources (GHSA / vendor advisories), **90 days** for taxonomy and curation (CWE / OWASP CSS / AppSec.fyi). The Phase 2.5 Stale Guard Check materializes this rule per run and the verdict is recorded in the PR-B body.
4. **Source + Evidence refs mandatory** — `Sources matched` and `Evidence refs` cells are never empty (recording a miss as `(직접 hit 없음)` still counts as filled)
5. **Scrub responsibility** — every row goes through scrub before PR; PR review is the gate, not the only check
6. **LLM_CONTEXT framing** — the row's `Used in` cell anchors it to a session, preserving the staging-layer framing
7. **PR-based only** — no direct commits to `security-field-notes`
8. **Append-only** — existing rows are not modified by the skill; if a row needs Last-verified refresh, that is a separate, human-initiated PR
9. **Semantic cache not authoritative** — any future cache layer caches only intermediate retrieval candidates or draft synthesis, never final verdicts

## Verification Checklist

A run is considered successful when:

- [ ] `category` resolves through `references/cwe-mapping.md` to a non-empty CWE list
- [ ] Phase 2 fetched all four sources (or recorded misses explicitly)
- [ ] Phase 2.5 Stale Guard check executed; verdict recorded in PR-B body
- [ ] Phase 3 synthesis contains GHSA id, commit short SHA, version range, CVSS, fix mechanism in ≤3 sentences
- [ ] Every Synthesis claim is backed by an Evidence-refs token
- [ ] Row passes column-count and pipe-spacing lint against existing ledger rows
- [ ] Scrub pass: no internal identifiers leaked into row or PR body
- [ ] PR-B opened against `windshock/security-field-notes` with `Used in` = `retrieval test (sec-reference-retrieval PoC slice <N>)`
- [ ] PR-B not auto-merged

## Failure Conditions

- **`category` not in `cwe-mapping.md`**: stop and report. Adding the mapping is a separate PR.
- **All four sources miss**: stop and report. A row with zero source hits is not useful (§14 Principle #4 requires `Sources matched` filled with at least one real hit, not just misses).
- **GHSA returns an already-recorded advisory**: skip, query next. Slice 1 does not deduplicate-by-update — a new advisory is required.
- **Scrub finds internal data after multiple sanitization attempts**: stop and report. The finding's `evidence_summary` may need redaction at the producer side.

## Resources

- `references/source-catalog.md` — per-source fetch verb + Evidence-refs token format
- `references/cwe-mapping.md` — category → CWE lookup
- `templates/ledger-row.md` — 8-column ledger row template + scrub checklist + calibration examples

## Related Reading

- `security-field-notes/AGENTS.md §14` — Pull-Side Synthesis Ledger Protocol (the governance contract this skill implements)
- `security-field-notes/knowledge/appsec/synthesis-ledger.md` — calibration anchor; the 3 backfill rows define the quality bar
- `security-field-notes/knowledge/appsec/2026-05-20-appsec-fyi-curation-library-survey.md` — multi-source design background
- [`oh-my-secuaudit` Issue #7](https://github.com/windshock/oh-my-secuaudit/issues/7) — PoC tracking
- [`security-field-notes` Issue #1](https://github.com/windshock/security-field-notes/issues/1) — push/pull catalog adoption
