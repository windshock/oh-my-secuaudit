# PoC Quality and Safety Standards

## Mandatory Criteria

Every PoC must satisfy all five:

| # | Criterion | Test |
|---|---|---|
| 1 | **Reproducible** | Another assessor runs it, gets the same result |
| 2 | **Self-contained** | All dependencies listed or containerized |
| 3 | **Non-destructive** | No data loss, no DoS, no permanent state change |
| 4 | **Documented** | README explains what it proves and what success looks like |
| 5 | **Versioned** | Tied to a specific target state (commit hash or snapshot date) |

## PoC README Template

Each `artifacts/poc/FINDING-NNN/README.md` must include:

1. **Finding reference**: `FINDING-NNN` with title and severity
2. **What this proves**: One sentence describing the vulnerability demonstrated
3. **Prerequisites**: Tools, access, environment needed
4. **Steps to reproduce**: Numbered, copy-pasteable commands
5. **Expected output**: What "success" (vulnerability confirmed) looks like
6. **Target state**: Commit hash, deployment version, or snapshot date tested against
7. **Safety notes**: Any precautions when running (e.g., "do not run against production")

## PoC Formats by Category

| Category | Recommended Format | Key Evidence |
|---|---|---|
| XSS | HTTP request file + browser screenshot | Injected payload in response |
| SQL Injection | HTTP request + DB query log | Data extraction or error-based confirmation |
| Auth bypass | Shell script with two scenarios | With-auth vs without-auth comparison |
| SSRF | HTTP request + server-side log | Internal resource access from external input |
| Deserialization | Payload generator + trigger script | Gadget chain execution evidence |
| XXE | XML payload + response capture | File read or SSRF via entity expansion |
| Fuzzing | Fuzzer config + corpus + crash | Crash log + minimized test case |
| Config weakness | Config diff (vulnerable vs hardened) | Impact demonstration |
| Hardcoded secret | grep/semgrep evidence + usage trace | Secret value location + where it's consumed |

## Safety Guidelines

- **Never** include working exploits for RCE without explicit authorization context in README.
- **Never** store actual target credentials, even in evidence files.
- **Redact** sensitive data (PII, internal IPs) in evidence captures before committing.
- **Prefer** detection-only PoCs over full exploitation where sufficient to prove the point.
- Mark any PoC that modifies target state with `## WARNING: STATE-MODIFYING` in README.

## Evidence Capture Best Practices

### HTTP Requests (.http format)
```http
### FINDING-001: XSS in search parameter
POST /api/search HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"query": "<script>alert(document.domain)</script>"}

### Response (captured 2026-03-15)
# HTTP/1.1 200 OK
# Content-Type: text/html
# <html>... <script>alert(document.domain)</script> ...</html>
```

### Command-line evidence
```bash
# Capture both command and output together
script -q /dev/null sh -c 'curl -s ...' | tee evidence/output.txt
```

### Config snapshots
- Save the exact configuration file, not a description of it.
- Include a diff against the hardened version when applicable.
