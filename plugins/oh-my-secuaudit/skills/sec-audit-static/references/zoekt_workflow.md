# Zoekt Workflow (Optional Accelerator)

Use Zoekt as a candidate prefilter for large repositories to reduce downstream scan scope.

## Goal
- Reduce file scope before Semgrep/Joern.
- Keep analysis non-blocking with strict `rg` fallback.

## Standard flow
1. Source pass
- `code_search.sh --repo <repo> --query '<sink-or-source-regex>' --engine auto`
- Convert selected hits to function contexts with `extract_function_context.py`.
- Feed narrowed candidates into Semgrep/Joern.

2. Decompiled pass (JVM buildable)
- Build and decompile first.
- Run the same command against `<repo>/decompiled`.
- Compare `source` vs `decompiled` findings and map to original paths where possible.

## Rules
- Do not require Zoekt for correctness.
- If Zoekt binaries are missing, index creation fails, or query fails: fallback to `rg` immediately.
- Keep candidate set bounded (recommended <= 50 files before deep flow checks).
- Preserve evidence extraction steps (`nl -ba`, `sed -n`) after candidate filtering.
- Function-context fallback improvement is mandatory:
  - tree-sitter primary language parse failure
  - retry with alternate language parser
  - brace-based block inference
  - fixed +/- line window as final fallback

## Environment
- Enable local Zoekt path with `ZOEKT_ENABLED=1`.
- Optional index root override: `ZOEKT_INDEX_ROOT=<path>`.

## Remote Zoekt (shared webserver) — offload indexing off the local disk
Instead of indexing each repo locally (`~/.cache/zoekt` can grow multi-GB), query a shared
`zoekt-webserver` that already holds the corpus. `engine=auto` prefers this when `ZOEKT_URL` is set.
- `ZOEKT_URL`  base URL, e.g. `http://localhost:6070` (k8s: `kubectl -n zoekt port-forward svc/zoekt 6070:6070`)
  or a NodePort such as `http://<worker-ip>:30670`.
- `ZOEKT_REPO` zoekt `r:` repo filter. Unset => derived from `basename(--repo)`; empty => whole index.
- The target repo must already be indexed on the server (index job / CronJob).
- Output is the same grep-style `path:line:content` as `rg`; any HTTP failure falls back to `rg`.

```bash
ZOEKT_URL=http://localhost:6070 ZOEKT_REPO=my-repo \
  code_search.sh --repo /path/to/my-repo --query '<sink-or-source-regex>' --engine auto
```

## Example
```bash
ZOEKT_ENABLED=1 \
~/.codex/skills/local/sec-audit-static/tools/scripts/code_search.sh \
  --repo /path/to/repo \
  --query '(@RequestBody|@RequestParam|Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder\\()' \
  --engine auto
```

```bash
~/.codex/skills/local/sec-audit-static/tools/scripts/extract_function_context.py \
  --hits /tmp/hits.txt \
  --out /tmp/function_context.json \
  --radius 40 \
  --max 30
```
