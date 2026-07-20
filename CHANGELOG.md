# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Renamed to `code-review-agent-mcp`** — better SEO, "agent" communicates AI/autonomy, available on PyPI
- Updated README with new name and "AI code review agent" positioning
- Updated tagline: "AI code review agent that doesn't sugarcoat"
- Security module (`security.py`) with input validation and sandboxing
- CI workflow (GitHub Actions, 3 OS × 3 Python versions)
- Publish workflow (PyPI trusted publisher, OIDC)
- SECURITY.md with threat model
- CONTRIBUTING.md
- This CHANGELOG.md

### Fixed
- **CRITICAL**: Git argument injection in `review_commit` — `commit_ref` is now validated against a strict whitelist; `--no-ext-diff` and `--no-textconv` prevent `.git/config` RCE.
- **CRITICAL**: Path traversal in `review_file` — file access is now sandboxed to the current working directory; sensitive paths (`.ssh`, `.aws`, `.env`) are refused.
- **HIGH**: Blocking `subprocess.run` in async function — now runs in `asyncio.to_thread`.
- **HIGH**: Blocking file I/O in async function — now runs in `asyncio.to_thread`.
- **HIGH**: System prompt passed twice (in user message AND as `systemPrompt`) — now only passed as `systemPrompt`.
- **HIGH**: Bare `except Exception` reported `**CLEAN**` on internal errors — now returns proper error message.
- **MEDIUM**: `ValidationError` uncaught in `call_tool` — now caught and returned as error message.
- **MEDIUM**: Dead `handle_list_tools` fallback in `server.py` — removed.
- **MEDIUM**: `snippet_01` `EXPECTED_LINE_REF` corrected from "5" to "7".

### Changed
- `review_file` now requires paths to be under the current working directory (set `BLUNT_REVIEW_ALLOW_ABSOLUTE=1` to override).
- `review_commit` now runs `git` with `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null` to prevent config-based attacks.
- LLM sampling calls now have a 120-second timeout.

## [0.1.0] - 2026-07-19

### Added
- Initial release
- 5 MCP tools: `review_code`, `review_file`, `review_diff`, `review_commit`, `list_severities`
- 4 harshness levels: `gentle`, `standard`, `brutal`, `kernel-maintainer`
- Anti-RLHF engineering with 3 layers:
  1. System prompt with 12 core principles
  2. Post-processor that strips 40+ banned phrases
  3. Validator that checks severity labels, line citations, verdict
- 5 benchmark snippets for regression testing
- 74 unit tests (all passing)
