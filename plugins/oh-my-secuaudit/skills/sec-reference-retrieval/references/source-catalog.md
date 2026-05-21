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
- **Slice 1 specific URLs**:
  - SSRF → `https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html`

### 3. GitHub Advisory Database (GHSA)

- **Role**: recent CVE + patch URL + affected version range
- **License**: public, official API
- **Fetch verb**: `gh api`
- **API pattern (search)**:
  ```
  gh api -X GET /advisories -F cwes=CWE-NNN -F per_page=20 -F sort=updated
  ```
- **API pattern (single advisory)**:
  ```
  gh api /advisories/GHSA-xxxx-yyyy-zzzz
  ```
- **Evidence-refs token format**: `GHSA-xxxx-yyyy-zzzz; commit:<short_sha>` — the commit SHA comes from the advisory's patch URL, typically `https://github.com/<owner>/<repo>/commit/<sha>`
- **Fallback**: `gh api graphql` if REST rate-limits

### 4. AppSec.fyi

- **Role**: curated discourse — recent practitioner notes per topic
- **License**: individual curation (Carl Sampson); attribution-only, do not mirror content
- **Fetch verb**: `WebFetch`
- **URL pattern**: `https://www.appsec.fyi/<topic>.html` (e.g., `ssrf.html`, `xss.html`, `idor.html`, `rce.html`)
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
