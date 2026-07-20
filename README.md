# Code Review Agent MCP

> AI code review agent that doesn't sugarcoat. If your code is bad, it tells you. Bluntly.

[![CI](https://github.com/frangelbarrera/code-review-agent-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/frangelbarrera/code-review-agent-mcp/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

An AI-powered MCP (Model Context Protocol) server that reviews your code the way experienced maintainers review patches on serious projects: technically, directly, without diplomacy.

## What it does

- **AI code review** — reviews code snippets, files, git diffs, and commits
- Returns findings with severity labels: `CRITICAL`, `MAJOR`, `MINOR`, `NIT`, `CLEAN`
- Cites specific line numbers for every finding
- Explains why something is bad, then how to fix it
- Ends with a clear verdict: "Ship it." or "Do not merge until..."
- **No false praise. No hedging. No apologies. No filler.**

## Why?

Most AI code reviewers are trained to be polite. They preface criticism with "great work but...", they hedge with "you might want to consider...", they soften findings with "this could potentially be an issue".

That's not how serious code review works. On real projects (Linux kernel, PostgreSQL, Redis, SQLite), maintainers review patches directly. They find problems and call them out clearly. They don't exist to make the author feel good — they exist to make the code better.

This MCP encodes that tradition. The personality IS the product.

## Anti-RLHF engineering

LLMs are RLHF-trained to be polite. This AI agent fights that with three layers:

1. **System prompt** — 12 core principles (code-not-coder, verdict-first, severity labels, line citations, no false praise, no hedging, no apologies, no filler, second person, no demographic references, no refusal, no hallucinated bugs)
2. **Post-processor** — strips 40+ banned phrases (hedging, softeners, apologies, filler) from LLM output
3. **Validator** — checks output has severity labels, line citations, and verdict; flags vague problem statements as hallucination signals

## Tools

| Tool | Description |
|------|-------------|
| `review_code` | Review a code snippet |
| `review_file` | Review a file from disk (sandboxed) |
| `review_diff` | Review a git diff |
| `review_commit` | Review a git commit (`git show <ref>`) |
| `list_severities` | List severity labels with definitions |

## Harshness levels

| Level | Behavior |
|-------|----------|
| `gentle` | Softens language slightly. Still reports all findings. |
| `standard` | Default blunt review. Direct, technical, no diplomacy. |
| `brutal` | No softening. "This is wrong." not "This should be changed." |
| `kernel-maintainer` | Maximum bluntness. Short sentences. Imperative voice. |

## Installation

```bash
pip install code-review-agent-mcp
```

Or with uv:

```bash
uv pip install code-review-agent-mcp
```

## Configuration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "code-review-agent": {
      "command": "python",
      "args": ["-m", "blunt_codereview.server"]
    }
  }
}
```

Or if installed via pip:

```json
{
  "mcpServers": {
    "code-review-agent": {
      "command": "blunt-codereview-mcp"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "code-review-agent": {
      "command": "python",
      "args": ["-m", "blunt_codereview.server"]
    }
  }
}
```

## Usage examples

### Review a code snippet

```
User: Review this code for me

def get_user(username):
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
```

MCP response:

```
## Code Review: snippet

### Findings

**CRITICAL** `snippet:7` — SQL injection
The query uses an f-string with user input, allowing SQL injection. Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`.

### Verdict

Do not merge until CRITICAL is fixed.
```

### Review a file

```
User: Review src/auth.py

MCP calls review_file with file_path="src/auth.py"
Returns blunt review with line citations.
```

### Review a commit

```
User: Review the last commit

MCP calls review_commit with commit_ref="HEAD"
Returns blunt review of the diff.
```

## Severity labels

| Label | When to use |
|-------|-------------|
| **CRITICAL** | Security vulnerability, data loss, deadlock, RCE, anything that ships broken |
| **MAJOR** | Logic error, race condition, resource leak, broken edge case, wrong abstraction |
| **MINOR** | Style, naming, missing test, redundant code, brittle assumption |
| **NIT** | Cosmetic, formatting, comment wording |
| **CLEAN** | Explicitly state when a section is fine. Prevents invented-bug bias. |

## Security

This MCP server implements security sandboxing:

- **File access** is sandboxed to the current working directory by default
- **Sensitive paths** (`.ssh`, `.aws`, `.env`, `/etc/passwd`, etc.) are refused
- **Git refs** are validated against a strict character whitelist to prevent option injection
- **Subprocess calls** use `shell=False` and disable global git config

See [SECURITY.md](SECURITY.md) for the full threat model.

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=blunt_codereview
```

## Benchmark snippets

The `benchmarks/` directory contains 5 regression snippets that verify the reviewer:

1. **SQL injection** — expects CRITICAL, line citation, "Do not merge"
2. **Mutable default** — expects MAJOR
3. **Clean code** (binary search) — expects CLEAN, "Ship it" (anti-hallucination test)
4. **Swallowed exception** — expects MAJOR
5. **Off-by-one** — expects MAJOR

The clean code benchmark is the most important — it catches hallucination. If the reviewer invents bugs in correct code, the anti-RLHF system is broken.

## License

MIT

## Acknowledgments

This project encodes the kernel maintainer tradition of code review — a methodology practiced by many senior engineers across many projects (Linux kernel, PostgreSQL, Redis, SQLite, and others). We cite the tradition, not any single practitioner.
