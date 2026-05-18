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
- Enable Zoekt path with `ZOEKT_ENABLED=1`.
- Optional index root override: `ZOEKT_INDEX_ROOT=<path>`.

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
