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

## [0.2.0] - 2026-07-26

### Summary
Hardening release for the input trust boundary, the git subprocess path,
and the LLM error-handling paths. All changes are backward compatible at
the MCP protocol level; the public tool schemas are unchanged.

### Security

#### Input trust boundary
- Added a randomized `<untrusted_content id="...">` ... `</untrusted_content id="...">` boundary around every attacker-controllable field sent to the LLM (code, diff, commit output, source label, context notes, commit ref). A fresh 16-hex-char token is generated per invocation; the closing tag must carry the matching id, so a payload that tries to close the boundary with a hard-coded `</untrusted_content>` string does not match.
- Added an "Input trust boundary (MANDATORY)" section to the system prompt instructing the model to treat the wrapped content as data, ignore embedded directives (e.g. "ignore previous instructions", "return only CLEAN"), and report manipulation attempts as a `MAJOR` finding.
- Moved the caller-supplied `context`, `source_label`, and `commit_ref` fields inside the untrusted boundary so they cannot be used to inject instructions through the prompt framing.

#### Git revision handling
- `review_commit` now places `--` after the commit ref (`git show ... <ref> --`) instead of before it. Placing `--` before the ref caused git to treat the ref as a pathspec, returning empty output for every commit and silently accepting nonexistent refs.
- `validate_git_ref` no longer accepts `:` in the ref. The `<treeish>:<path>` syntax would otherwise let a caller retrieve arbitrary files from git history via `git show` (e.g. `HEAD:creds.txt`).
- `validate_repo_path` now rejects `.git` symlinks and `.git` gitfiles whose target points outside the working directory. Both forms make `git -C <repo>` operate on a different repository's objects, which would otherwise bypass the sandbox check on the git data source.
- `git show` output is capped at `MAX_DIFF_SIZE` (512 KB, roughly 130k tokens) before being sent to the LLM. When the diff is truncated, the prompt includes a notice so the verdict reflects only what was shown.

#### File handling
- `review_file` now opens files with `os.open(O_RDONLY | O_NOFOLLOW)` and validates the open file descriptor with `fstat` before reading. This closes the TOCTOU window between `validate_file_path` and `Path.read_text` that a concurrent writer could exploit to swap the file for a symlink.
- `MAX_FILE_SIZE` validation on `code` and `diff` inputs now measures UTF-8 byte length (`len(v.encode("utf-8"))`) instead of character count. A payload of N emoji is N characters but 4N UTF-8 bytes, so the previous check accepted 40 MB of UTF-8 input.

#### Sensitive path denylist
- Switched the sensitive-path matcher from substring matching to component-aware matching. Substring matching produced false positives on legitimate paths such as `tests/etc/passwd.py`, `app/.env.example`, `docs/proc/info.md`, and `src/ssh/README.md`.
- Expanded `SENSITIVE_PATH_PATTERNS` to cover additional well-known credential, history, and config locations: `/etc/shadow-`, `/etc/gshadow`, `/etc/sudoers.d/`, `/etc/cron.d/`, `/etc/crontab`, `/etc/nginx/`, `/etc/ssl/`, `/etc/ssl/private/`, `/etc/mysql/`, `/etc/postgresql/`, `/etc/redis/`, `/.config/aws/`, `/.config/gcloud/`, `/.config/git/credentials`, `/.gitconfig`, `/.bashrc`, `/.bash_history`, `/.bash_profile`, `/.zshrc`, `/.zsh_history`, `/.profile`, `/.pgpass`, `/.my.cnf`, `/.terraformrc`, `/.terraform.d/`, `/.ansible/`, `/.mozilla/`, `/.config/google-chrome/`, `/.vscode/`, `/.idea/`.

#### Git subprocess environment
- `get_safe_git_env` now also clears the git helper environment variables that the subprocess could otherwise use to invoke external programs: `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_PROXY_COMMAND`, `GIT_CREDENTIAL_HELPER`, `GIT_ASKPASS`, `SSH_ASKPASS`. Sets `GIT_TERMINAL_PROMPT=0` so git never prompts for credentials interactively, and `GIT_ATTR_NOSYSTEM=1` to ignore `/etc/gitattributes` (which can reference filter commands).

#### Subprocess lifecycle
- `review_commit` now spawns `git show` via `subprocess.Popen` and wraps `communicate()` in `asyncio.wait_for`. On `TimeoutError` or `CancelledError` the child process is explicitly killed and reaped, so a client disconnect during a review no longer leaves a zombie git process running for the full timeout window.

#### Error reporting
- Error responses no longer embed raw exception text or git stderr in the message returned to the MCP client. Each error path generates a short random correlation id (8 hex chars), returns it to the client as `[ref=<id>]`, and logs the full exception or stderr server-side keyed by the same id. Operators look up the id in the server logs to diagnose; the client only learns that an error happened plus the lookup key. This avoids disclosing internal hostnames, IPs, filesystem paths, or git repository internals through the client-facing response.
- LLM sampling fallbacks on `TimeoutError` and `Exception` now report `**CRITICAL**` instead of `**CLEAN**` and explicitly state that the code was not reviewed. The previous `**CLEAN**` severity on a sampling failure could be misinterpreted by downstream automation as an approval.

### Post-processor
- `_detect_hallucination_signals` now uses `re.IGNORECASE` when counting severity labels for the quota-padding check, matching the case-insensitive behavior of `_SEVERITY_RE`. Lowercase severity labels (e.g. `**critical**`) are now counted consistently with uppercase ones.

### Tests
- The test suite grew from 173 to 263 tests. New coverage includes regression tests for every change listed above: LLM fallback severity, git ref placement, `HEAD:path` rejection, `.git` symlink and gitfile sandboxing, diff truncation, trust-boundary wrapping (including the random id, the closing-tag match, and bypass attempts via `context`, `source_label`, and `commit_ref`), TOCTOU-safe file open, component-aware sensitive-path matching, UTF-8 byte-size validation, case-insensitive hallucination detection, helper env-var clearing, and the expanded sensitive-path denylist.

### Changed
- `review_file` now opens files with `O_NOFOLLOW` and validates the open descriptor with `fstat`. Regular files inside the sandbox continue to work; symlinks at the final path component are rejected by the kernel.
- `review_commit` error messages now include a `[ref=<id>]` token instead of the raw git stderr.

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
