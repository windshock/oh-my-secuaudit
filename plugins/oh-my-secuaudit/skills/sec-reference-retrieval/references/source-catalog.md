# Source Catalog for sec-reference-retrieval

This file documents the four upstream sources queried in Phase 2 of the cascading filter. For each, it specifies: the fetch verb, the URL pattern, the Evidence-refs token format, and the license note.

The catalog is intentionally narrow in slice 1. Adding a source is a separate PR.

## Registered Sources

### 1. CWE (cwe.mitre.org)

- **Role**: canonical definition + historical observed-CVE links
- **License**: public domain
- **Fetch verb**: `WebFetch`
- **URL pattern**: `https://cwe.mitre.org/data/definitions/<NNN>.html`
- **Evidence-refs token format**: `CWE-NNN`
- **Note**: the canonical definition page lists "Observed Examples" — useful for cross-checking GHSA matches

### 2. OWASP Cheat Sheet Series (cheatsheetseries.owasp.org)

- **Role**: language-specific fix patterns + secure code examples
- **License**: CC BY-SA 4.0 (do not mirror; link only)
- **Fetch verb**: `WebFetch`
- **URL pattern**: `https://cheatsheetseries.owasp.org/cheatsheets/<Sheet_Name>_Cheat_Sheet.html`
- **Evidence-refs token format**: `OWASP <Sheet Name> Cheat Sheet`
- **Per-category URLs**:
  - SSRF → `https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html` (slice 1)
  - XSS → primary: `https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html`; supplementary: `DOM_based_XSS_Prevention_Cheat_Sheet.html`, `HTML5_Security_Cheat_Sheet.html` (slice 2)

### 3. GitHub Advisory Database (GHSA)

- **Role**: recent CVE + patch URL + affected version range
- **License**: public, official API
- **Fetch verb**: `gh api`
- **API pattern (search by CWE)** — note: numeric CWE ID only; `CWE-` prefix MUST be stripped:
  ```
  # CWE-918 → numeric 918
  gh api "/advisories?cwes=918&per_page=20&sort=updated"
  ```
  Confirmed 2026-05-22: `cwes=CWE-918` returns zero results (silent failure); `cwes=918` returns the expected list. This is a GHSA REST API quirk — the response shape preserves `CWE-NNN` in the `cwes[].cwe_id` field, only the *query parameter* requires the numeric form.
- **API pattern (single advisory)**:
  ```
  gh api /advisories/GHSA-xxxx-yyyy-zzzz
  ```
- **API pattern (patch commit recovery)** — if the advisory text does not link a commit directly, search the upstream repo's path history:
  ```
  gh api "/repos/<owner>/<repo>/commits?path=<vulnerable-file>&per_page=10"
  ```
  Look for a commit whose message references the fix (e.g., "fix: validate redirect URL protocol"). Slice-2 NocoDB precedent.
- **Evidence-refs token format**: `GHSA-xxxx-yyyy-zzzz; commit:<short_sha>` — the commit SHA comes from the advisory's patch URL (typically `https://github.com/<owner>/<repo>/commit/<sha>`) or from the path-history recovery above.
- **Fallback**: `gh api graphql` if REST rate-limits.

### 4. AppSec.fyi

- **Role**: curated discourse — recent practitioner notes per topic
- **License**: individual curation (Carl Sampson); attribution-only, do not mirror content
- **Fetch verb**: `WebFetch`
- **URL pattern**: `https://www.appsec.fyi/<topic>.html`
- **Per-category URLs (confirmed)**:
  - SSRF → `https://www.appsec.fyi/ssrf.html` (slice 1)
  - XSS → `https://www.appsec.fyi/xss.html` (slice 2)
- Other candidate topic pages (unverified URL slug, confirm on first fetch): `idor.html`, `rce.html`, `sqli.html`, `deserialization.html`
- **Evidence-refs token format**: `AppSec.fyi #<entry-number>` (the curation entries are numbered on each topic page)
- **No-hit handling**: if AppSec.fyi has no entries matching the candidate, record explicitly as `(AppSec.fyi 직접 hit 없음)` in the `Sources matched` cell. Axios NO_PROXY (2026-05-21 ledger row) is the precedent.

## Excluded Sources

| Source | Reason |
|---|---|
| Fortify Vulncat (`vulncat.fortify.com`) | `robots.txt` blocks AI/bot access; OpenText ToS prohibits high-volume automated access. SSC API / SCA rulepack license channel inquiry pending; if vendor permits, this source may be re-added in a later slice. |

## Adding a Source

1. Confirm license / ToS / robots.txt allows automated query
2. Document fetch verb, URL pattern, token format here
3. Update `references/README.md` in `security-field-notes` to register the source
4. Update `cwe-mapping.md` if the new source covers new CWEs
5. Open PRs on both repos referencing each other
