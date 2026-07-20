# Contributing to Code Review Agent MCP

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/frangelbarrera/code-review-agent-mcp.git
cd code-review-agent-mcp

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=blunt_codereview
```

## Project Structure

```
src/blunt_codereview/
├── __init__.py
├── server.py              # MCP server entry point
├── security.py            # Input validation & sandboxing
├── prompts/
│   └── system_prompt.py   # The system prompt (the heart of the product)
├── tools/
│   └── review.py          # MCP tool implementations
└── validators/
    └── post_processor.py  # Anti-RLHF post-processor

tests/                     # Unit + stress tests
benchmarks/                # Regression snippets for LLM-based testing
examples/                  # Usage examples
```

## How to Contribute

### Reporting Bugs

Open a GitHub issue with:
- What you expected
- What actually happened
- Minimal reproduction steps
- Your environment (Python version, MCP client, OS)

### Suggesting Features

Open a GitHub issue with the `enhancement` label. Describe:
- The use case
- The proposed solution
- Alternatives considered

### Pull Requests

1. Fork the repo
2. Create a branch: `git checkout -b fix/my-fix`
3. Make your changes
4. Add tests for your changes
5. Run tests: `pytest`
6. Commit with a clear message
7. Open a PR

### Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` tests only
- `refactor:` code change that neither fixes a bug nor adds a feature
- `perf:` performance improvement
- `chore:` build/tooling changes

Example: `feat: add review_pr tool for GitHub PRs`

## Testing

### Unit Tests

All code changes must include tests. Run:

```bash
pytest tests/ -v
```

### Benchmark Regression Tests

The `benchmarks/` directory contains 5 snippets that verify the reviewer catches real bugs and doesn't hallucinate. If you change the system prompt or post-processor, run the LLM regression test (requires an MCP client):

```bash
python tests/test_llm_regression.py
```

### Security Tests

If you change `security.py` or the tool handlers, verify:

```bash
pytest tests/test_security.py -v
```

## Code Style

- Python 3.10+
- Type hints required
- Docstrings for public functions
- PEP 8 (ruff enforces)
- No `print()` in library code — use `logging`

## Architecture Decisions

### Why client sampling (not direct Anthropic API)?

The MCP `sampling/createMessage` primitive lets the client (Claude Desktop, Cursor) provide the LLM. This means:
- No API key needed
- Works with any LLM the client supports
- No cost to the user beyond their existing LLM subscription

### Why a post-processor?

LLMs are RLHF-trained to be polite. Even with a strict system prompt, they hedge and soften. The post-processor is a defense-in-depth layer that catches what the prompt doesn't.

### Why sandbox file access?

An MCP server runs with the user's permissions. Without sandboxing, a malicious client could read `~/.ssh/id_rsa` or `/etc/passwd` via `review_file`. The sandbox restricts access to the current working directory.

## Release Process

1. Update `CHANGELOG.md`
2. Bump version in `pyproject.toml` and `src/blunt_codereview/__init__.py`
3. Create a git tag: `git tag v0.X.Y`
4. Push the tag: `git push origin v0.X.Y`
5. Create a GitHub Release — the publish workflow will auto-publish to PyPI

## Questions?

Open a GitHub issue with the `question` label.
