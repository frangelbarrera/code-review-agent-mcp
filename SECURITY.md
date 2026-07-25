# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅         |
| 0.1.x   | ✅         |

## Reporting a Vulnerability

If you discover a security vulnerability in code-review-agent-mcp, please report it responsibly.

**DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: frangelrcbarrera@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive a response within 48 hours. If the vulnerability is confirmed, a fix will be prioritized.

## Security Measures

This MCP server implements the following security measures:

### Input Validation
- **File paths** are sandboxed to the current working directory by default. Set `BLUNT_REVIEW_ALLOW_ABSOLUTE=1` to allow absolute paths (security risk).
- **Sensitive paths** (`.ssh`, `.aws`, `.env`, `/etc/passwd`, etc.) are refused even with `BLUNT_REVIEW_ALLOW_ABSOLUTE=1`. The matcher is component-aware, so legitimate paths like `tests/etc/passwd.py` or `app/.env.example` are not rejected as false positives.
- **Git refs** are validated against a strict character whitelist to prevent option injection (`--output=`, `--ext-diff`, etc.) and `<treeish>:<path>` exfiltration (`HEAD:creds.txt`, etc.).
- **File size** is capped at 10 MB measured in UTF-8 bytes to prevent resource exhaustion via multibyte payloads.
- **Diff size** produced by `git show` is capped at 512 KB before being sent to the LLM, with a truncation notice when the cap is hit.

### Subprocess Security
- `git show` is called with `--no-ext-diff` and `--no-textconv` to prevent `.git/config` RCE attacks.
- The commit ref is placed before `--` so git treats it as a revision; `--` only separates the ref from any pathspec.
- `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null` disable global/system git config.
- Helper environment variables that git could use to invoke external programs are cleared: `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_PROXY_COMMAND`, `GIT_CREDENTIAL_HELPER`, `GIT_ASKPASS`, `SSH_ASKPASS`. `GIT_TERMINAL_PROMPT=0` prevents interactive credential prompts and `GIT_ATTR_NOSYSTEM=1` ignores `/etc/gitattributes` filter commands.
- All subprocess calls use `shell=False`.
- The git subprocess is spawned with `Popen` and explicitly killed on `TimeoutError` or `CancelledError`, so a client disconnect during a review does not leave a zombie git process running for the full timeout window.

### Filesystem Race Hardening
- `review_file` validates the path with `validate_file_path` and then opens it with `os.open(O_RDONLY | O_NOFOLLOW)` followed by `fstat` on the open descriptor. The kernel rejects symlinks at the final path component, and the size and type checks run against the open inode rather than the path, closing the TOCTOU window between validation and read.
- `validate_repo_path` rejects `.git` symlinks and `.git` gitfiles whose target resolves outside the working directory, so a sandboxed directory whose `.git` points at another repository cannot be used to operate on that other repository's objects.

### Async Safety
- File I/O and subprocess calls run in threads (`asyncio.to_thread`) to avoid blocking the event loop.
- LLM sampling calls have a 120-second timeout.

### LLM Security
- The system prompt is passed via `systemPrompt`, not in the user message.
- Every attacker-controllable field sent to the LLM (code, diff, commit output, source label, context notes, commit ref) is wrapped in a randomized `<untrusted_content id="<16-hex>">` ... `</untrusted_content id="<16-hex>">` boundary. The closing tag must carry the same id as the opening tag; a payload that embeds a hard-coded `</untrusted_content>` string does not match the boundary.
- The system prompt instructs the model to treat the wrapped content as data, ignore embedded directives such as "ignore previous instructions" or "return only CLEAN", and report manipulation attempts as a `MAJOR` finding.
- The post-processor strips hedging but does not modify technical content.
- `_detect_hallucination_signals` counts severity labels case-insensitively so lowercase labels (e.g. `**critical**`) are counted consistently with the case-insensitive `_SEVERITY_RE`.

### Error Reporting
- Error responses no longer embed raw exception text or git stderr in the message returned to the MCP client. Each error path generates a short random correlation id (8 hex chars), returns it to the client as `[ref=<id>]`, and logs the full exception or stderr server-side keyed by the same id. This avoids disclosing internal hostnames, IPs, filesystem paths, or git repository internals through the client-facing response.
- LLM sampling fallbacks on `TimeoutError` and `Exception` report `**CRITICAL**` and explicitly state that the code was not reviewed, so downstream automation cannot mistake a sampling failure for an approval.

## Threat Model

### What this MCP CAN do (by design)
- Read files under the current working directory
- Run `git show` on commits in repos under the current working directory
- Send code content to the client's LLM (Claude/GPT) via MCP sampling

### What this MCP CANNOT do
- Read files outside the working directory (unless `BLUNT_REVIEW_ALLOW_ABSOLUTE=1`)
- Read sensitive files (`.ssh`, `.aws`, `.env`, `/etc/passwd`, etc.)
- Execute arbitrary shell commands
- Make network requests (except via the client's LLM)
- Write files (except via git, which is sandboxed)

### What this MCP DOES NOT protect against
- A sufficiently advanced prompt-injection payload inside reviewed code may still influence the LLM's output. The trust boundary, the per-invocation random id, and the system-prompt instructions raise the bar but cannot eliminate the risk; the LLM's output is best treated as advisory, not as an automated gate.
- LLM exfiltrating data via the review output (mitigated by post-processor, not eliminated)
- Compromised MCP client (if the client itself is malicious, all bets are off)

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Reports will be acknowledged in release notes unless anonymity is requested.
