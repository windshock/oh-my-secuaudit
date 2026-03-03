# Tooling (Code Browser)

Use fast local code-browser tooling to minimize token usage:

- `rg` (ripgrep): primary search tool
- `zoekt` + `zoekt-index` (optional): high-speed prefilter for large repositories
- `ctags` (optional): symbol navigation
- `tree-sitter` (optional): syntax-aware navigation when `rg/ctags` are insufficient
- `sed`/`awk`/`nl`: context extraction with line numbers

Preferred workflow:
1) Candidate prefilter: `code_search.sh --engine auto` (`zoekt` if enabled/available, else `rg`)
2) Function context extraction: `extract_function_context.py` on selected `file:line` hits
3) `nl -ba` + `sed -n` for targeted evidence when function extraction is insufficient
4) Only expand context when needed

Notes:
- Keep Zoekt optional. Never block analysis on missing Zoekt binaries/index.
- Normalize output to `file:line[:col]:snippet` when possible before passing to downstream scripts.
- Function extraction fallback policy:
  - `tree-sitter (primary language)` -> `tree-sitter (alternate language)` -> `brace fallback` -> `+/-N line window`
