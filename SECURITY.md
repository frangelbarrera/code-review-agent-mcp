# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
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
- **Sensitive paths** (`.ssh`, `.aws`, `.env`, `/etc/passwd`, etc.) are refused even with `BLUNT_REVIEW_ALLOW_ABSOLUTE=1`.
- **Git refs** are validated against a strict character whitelist to prevent option injection (`--output=`, `--ext-diff`, etc.).
- **File size** is capped at 10 MB to prevent resource exhaustion.

### Subprocess Security
- `git show` is called with `--no-ext-diff` and `--no-textconv` to prevent `.git/config` RCE attacks.
- `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null` disable global/system git config.
- All subprocess calls use `shell=False`.

### Async Safety
- File I/O and subprocess calls run in threads (`asyncio.to_thread`) to avoid blocking the event loop.
- LLM sampling calls have a 120-second timeout.

### LLM Security
- The system prompt is passed via `systemPrompt`, not in the user message, to prevent prompt injection from reviewed code.
- The post-processor strips hedging but does not modify technical content.

## Threat Model

### What this MCP CAN do (by design)
- Read files under the current working directory
- Run `git show` on commits in repos under the current working directory
- Send code content to the client's LLM (Claude/GPT) via MCP sampling

### What this MCP CANNOT do
- Read files outside the working directory (unless `BLUNT_REVIEW_ALLOW_ABSOLUTE=1`)
- Read sensitive files (`.ssh`, `.aws`, `.env`, etc.)
- Execute arbitrary shell commands
- Make network requests (except via the client's LLM)
- Write files (except via git, which is sandboxed)

### What this MCP DOES NOT protect against
- Prompt injection via reviewed code (the LLM may be tricked by malicious code comments)
- LLM exfiltrating data via the review output (mitigated by post-processor, not eliminated)
- Compromised MCP client (if the client itself is malicious, all bets are off)

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Reports will be acknowledged in release notes unless anonymity is requested.
