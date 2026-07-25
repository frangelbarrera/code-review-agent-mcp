"""MCP tool implementations for code review.

Each tool wraps the LLM call, applies the system prompt, and post-processes
the output to enforce blunt review style.

Security: All file and git operations go through the security module
which sandboxes access to the current working directory and validates
inputs against injection attacks.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field, field_validator

from ..prompts.system_prompt import SYSTEM_PROMPT
from ..validators.post_processor import enforce_blunt_output
from ..security import (
    SecurityError,
    validate_file_path,
    validate_git_ref,
    validate_repo_path,
    get_safe_git_env,
    MAX_FILE_SIZE,
)


# ---------------------------------------------------------------------------
# Argument schemas
# ---------------------------------------------------------------------------

_HARSHNESS_VALUES = {"gentle", "standard", "brutal", "kernel-maintainer"}


def _validate_harshness(v: str) -> str:
    if v not in _HARSHNESS_VALUES:
        raise ValueError(
            f"harshness must be one of {sorted(_HARSHNESS_VALUES)}, got '{v}'"
        )
    return v


class ReviewCodeArgs(BaseModel):
    code: str = Field(..., description="The code to review.")
    language: str = Field(default="auto", description="Programming language (auto-detect if 'auto').")
    context: str = Field(default="", description="Optional context.")
    harshness: str = Field(default="standard", description="Review harshness.")

    @field_validator("harshness")
    @classmethod
    def _v(cls, v: str) -> str:
        return _validate_harshness(v)

    @field_validator("code")
    @classmethod
    def _code_size(cls, v: str) -> str:
        if len(v) > MAX_FILE_SIZE:
            raise ValueError(f"Code too large: {len(v)} bytes (max {MAX_FILE_SIZE})")
        return v


class ReviewFileArgs(BaseModel):
    file_path: str = Field(..., description="Absolute path to the file to review.")
    harshness: str = Field(default="standard", description="Review harshness.")

    @field_validator("harshness")
    @classmethod
    def _v(cls, v: str) -> str:
        return _validate_harshness(v)


class ReviewDiffArgs(BaseModel):
    diff: str = Field(..., description="Git diff content to review.")
    harshness: str = Field(default="standard", description="Review harshness.")

    @field_validator("harshness")
    @classmethod
    def _v(cls, v: str) -> str:
        return _validate_harshness(v)

    @field_validator("diff")
    @classmethod
    def _diff_size(cls, v: str) -> str:
        if len(v) > MAX_FILE_SIZE:
            raise ValueError(f"Diff too large: {len(v)} bytes (max {MAX_FILE_SIZE})")
        return v


class ReviewCommitArgs(BaseModel):
    repo_path: str = Field(default=".", description="Path to the git repository.")
    commit_ref: str = Field(..., description="Commit reference (hash, HEAD, branch).")
    harshness: str = Field(default="standard", description="Review harshness.")

    @field_validator("harshness")
    @classmethod
    def _v(cls, v: str) -> str:
        return _validate_harshness(v)


# ---------------------------------------------------------------------------
# Harshness modifiers (appended to system prompt)
# ---------------------------------------------------------------------------

HARSHNESS_MODIFIERS = {
    "gentle": (
        "\n\n## Harshness: GENTLE\n"
        "Soften the language slightly. Use 'should' instead of 'must'. "
        "Still report all findings, but frame fixes as suggestions. "
        "Keep severity labels. Still no false praise."
    ),
    "standard": "\n\n## Harshness: STANDARD\nDefault blunt review. Direct, technical, no diplomacy.",
    "brutal": (
        "\n\n## Harshness: BRUTAL\n"
        "No softening. 'This is wrong.' not 'This should be changed.' "
        "One-word verdicts are acceptable. 'Wrong.' 'Broken.' 'No.'"
    ),
    "kernel-maintainer": (
        "\n\n## Harshness: KERNEL-MAINTAINER\n"
        "Maximum bluntness. Assume the author is experienced. "
        "Short sentences. Imperative voice. 'Fix this.' 'Wrong.' 'No.' "
        "If the code is garbage, say so. Still: code, not coder."
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_language(code: str) -> str:
    """Detect programming language from code content (heuristic)."""
    stripped = code.strip()
    if not stripped:
        return "unknown"
    if stripped.startswith(("def ", "import ", "from ", "class ")):
        return "python"
    if "function " in code or "const " in code or "let " in code or "var " in code:
        return "javascript"
    if "#include" in code or "int main(" in code:
        return "c"
    if "package " in code and "func " in code:
        return "go"
    if "public class" in code or "private " in code:
        return "java"
    if "fn " in code or "impl " in code:
        return "rust"
    if "<?php" in code:
        return "php"
    if stripped.startswith(("#!/bin/bash", "#!/bin/sh")):
        return "bash"
    return "unknown"


def _line_number_code(code: str) -> str:
    """Add line numbers to code for citation reference."""
    lines = code.splitlines()
    return "\n".join(f"{i:4d} | {line}" for i, line in enumerate(lines, 1))


def _build_review_prompt(code: str, language: str, context: str, harshness: str, source_label: str) -> str:
    """Build the user prompt for code review (system prompt is passed separately)."""
    if language == "auto":
        language = _detect_language(code)
    numbered = _line_number_code(code)
    parts = [f"Review the following {language} code.", f"Source: {source_label}"]
    if context:
        parts.append(f"\nContext: {context}")
    parts.append(f"\n```{language}\n{numbered}\n```")
    parts.append(
        "\nApply the review format from your instructions. "
        "Every finding needs a severity label, a line citation, and a fix. "
        "End with a Verdict section."
    )
    return "\n".join(parts)


async def _call_llm_via_sampling(server: Server, system_prompt: str, user_prompt: str) -> str:
    """Call the LLM via the MCP sampling primitive.

    Uses the client's LLM (Claude/GPT/etc.) — no API key needed.
    Falls back to an error message if sampling is not supported.
    """
    try:
        result = await asyncio.wait_for(
            server.request_context.session.request(
                "sampling/createMessage",
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": user_prompt},
                        }
                    ],
                    "maxTokens": 4096,
                    "systemPrompt": system_prompt,
                },
            ),
            timeout=120.0,
        )
        if hasattr(result, "content"):
            if isinstance(result.content, list):
                for item in result.content:
                    if hasattr(item, "text"):
                        return item.text
            elif hasattr(result.content, "text"):
                return result.content.text
        return str(result.content if hasattr(result, "content") else result)
    except asyncio.TimeoutError:
        return (
            "## Code Review: snippet\n\n### Findings\n\n"
            "**CRITICAL** `llm` — LLM sampling timed out\n"
            "LLM sampling timed out after 120 seconds. The code was NOT reviewed.\n\n"
            "### Verdict\n\nCannot review — LLM timeout. Do not merge."
        )
    except Exception as e:
        return (
            "## Code Review: snippet\n\n### Findings\n\n"
            "**CRITICAL** `llm` — LLM sampling unavailable\n"
            f"LLM sampling failed: {type(e).__name__}. "
            "Configure your MCP client (Claude Desktop, Cursor) to enable sampling. "
            "The code was NOT reviewed.\n\n"
            "### Verdict\n\nCannot review without LLM. Do not merge."
        )


def _format_security_error(err: SecurityError) -> str:
    """Format a SecurityError as a blunt review error message."""
    return (
        f"## Code Review: blocked\n\n"
        f"### Findings\n\n"
        f"**CRITICAL** `security` — Input rejected\n"
        f"{err}\n\n"
        f"### Verdict\n\nCannot review — security validation failed."
    )


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register_review_tools(server: Server) -> None:
    """Register all code review tools with the MCP server."""

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="review_code",
                description=(
                    "Review a code snippet bluntly. Returns a kernel-maintainer-style "
                    "code review with severity labels (CRITICAL/MAJOR/MINOR/NIT/CLEAN), "
                    "line citations, and fixes. No false praise, no hedging."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The code to review."},
                        "language": {"type": "string", "description": "Programming language.", "default": "auto"},
                        "context": {"type": "string", "description": "Optional context.", "default": ""},
                        "harshness": {
                            "type": "string",
                            "description": "Review harshness.",
                            "enum": ["gentle", "standard", "brutal", "kernel-maintainer"],
                            "default": "standard",
                        },
                    },
                    "required": ["code"],
                },
            ),
            Tool(
                name="review_file",
                description=(
                    "Review a file from disk. Sandboxed to the current working directory. "
                    "Reads the file, adds line numbers, returns a blunt code review."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the file (relative to cwd, or absolute if allowed)."},
                        "harshness": {
                            "type": "string",
                            "description": "Review harshness.",
                            "enum": ["gentle", "standard", "brutal", "kernel-maintainer"],
                            "default": "standard",
                        },
                    },
                    "required": ["file_path"],
                },
            ),
            Tool(
                name="review_diff",
                description="Review a git diff. Returns blunt review of the changes.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "diff": {"type": "string", "description": "Git diff content."},
                        "harshness": {
                            "type": "string",
                            "description": "Review harshness.",
                            "enum": ["gentle", "standard", "brutal", "kernel-maintainer"],
                            "default": "standard",
                        },
                    },
                    "required": ["diff"],
                },
            ),
            Tool(
                name="review_commit",
                description=(
                    "Review a git commit. Runs `git show <ref>` with security sandboxing. "
                    "Repo must be under the current working directory."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string", "description": "Path to git repo (default: cwd).", "default": "."},
                        "commit_ref": {"type": "string", "description": "Commit ref (hash, HEAD, branch)."},
                        "harshness": {
                            "type": "string",
                            "description": "Review harshness.",
                            "enum": ["gentle", "standard", "brutal", "kernel-maintainer"],
                            "default": "standard",
                        },
                    },
                    "required": ["commit_ref"],
                },
            ),
            Tool(
                name="list_severities",
                description="List severity labels with definitions.",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            if name == "review_code":
                args = ReviewCodeArgs(**arguments)
                return await _handle_review_code(server, args)
            elif name == "review_file":
                args = ReviewFileArgs(**arguments)
                return await _handle_review_file(server, args)
            elif name == "review_diff":
                args = ReviewDiffArgs(**arguments)
                return await _handle_review_diff(server, args)
            elif name == "review_commit":
                args = ReviewCommitArgs(**arguments)
                return await _handle_review_commit(server, args)
            elif name == "list_severities":
                return await _handle_list_severities()
            else:
                return [TextContent(type="text", text=f"Unknown tool: {name}.")]
        except SecurityError as e:
            return [TextContent(type="text", text=_format_security_error(e))]
        except Exception as e:
            return [TextContent(
                type="text",
                text=(
                    f"## Code Review: error\n\n### Findings\n\n"
                    f"**CRITICAL** `internal` — Tool error\n"
                    f"{type(e).__name__}: {e}\n\n"
                    f"### Verdict\n\nCannot review — internal error."
                ),
            )]

    async def _handle_review_code(server: Server, args: ReviewCodeArgs) -> list[TextContent]:
        harshness_mod = HARSHNESS_MODIFIERS.get(args.harshness, HARSHNESS_MODIFIERS["standard"])
        system = SYSTEM_PROMPT + harshness_mod
        user_prompt = _build_review_prompt(
            code=args.code, language=args.language, context=args.context,
            harshness=args.harshness, source_label="snippet",
        )
        raw_output = await _call_llm_via_sampling(server, system, user_prompt)
        cleaned, validation = enforce_blunt_output(raw_output)
        result = cleaned
        if validation.issues:
            result += "\n\n---\n\n<!-- post-processor notes:\n"
            for issue in validation.issues:
                result += f"- {issue}\n"
            result += f"- hedges_stripped: {validation.hedge_count}\n"
            result += "-->"
        return [TextContent(type="text", text=result)]

    async def _handle_review_file(server: Server, args: ReviewFileArgs) -> list[TextContent]:
        # Validate path (security)
        try:
            file_path = validate_file_path(args.file_path)
        except SecurityError as e:
            return [TextContent(type="text", text=_format_security_error(e))]

        # Read file in thread (non-blocking)
        try:
            code = await asyncio.to_thread(file_path.read_text, encoding="utf-8", errors="replace")
        except PermissionError:
            return [TextContent(
                type="text",
                text=f"## Code Review: {file_path.name}\n\n### Findings\n\n**CRITICAL** `{file_path.name}` — Permission denied\n\n### Verdict\n\nCannot read file.",
            )]
        except OSError as e:
            return [TextContent(
                type="text",
                text=f"## Code Review: {file_path.name}\n\n### Findings\n\n**CRITICAL** `{file_path.name}` — Read error: {e}\n\n### Verdict\n\nCannot read file.",
            )]

        if not code.strip():
            return [TextContent(
                type="text",
                text=f"## Code Review: {file_path.name}\n\n### Findings\n\n**MINOR** `{file_path.name}` — Empty file\nNothing to review.\n\n### Verdict\n\nEmpty file. Nothing to review.",
            )]

        language = file_path.suffix.lstrip(".") or "unknown"
        harshness_mod = HARSHNESS_MODIFIERS.get(args.harshness, HARSHNESS_MODIFIERS["standard"])
        system = SYSTEM_PROMPT + harshness_mod
        user_prompt = _build_review_prompt(
            code=code, language=language, context=f"File: {file_path}",
            harshness=args.harshness, source_label=str(file_path.name),
        )
        raw_output = await _call_llm_via_sampling(server, system, user_prompt)
        cleaned, _ = enforce_blunt_output(raw_output)
        return [TextContent(type="text", text=cleaned)]

    async def _handle_review_diff(server: Server, args: ReviewDiffArgs) -> list[TextContent]:
        if not args.diff.strip():
            return [TextContent(
                type="text",
                text="## Code Review: empty diff\n\n### Findings\n\n**MINOR** — Empty diff\nNothing changed.\n\n### Verdict\n\nNothing to review.",
            )]
        harshness_mod = HARSHNESS_MODIFIERS.get(args.harshness, HARSHNESS_MODIFIERS["standard"])
        system = SYSTEM_PROMPT + harshness_mod
        user_prompt = (
            "Review the following git diff. Focus on what changed.\n\n"
            f"```diff\n{args.diff}\n```\n\n"
            "Apply the review format. Every finding needs a severity label, line citation, and fix."
        )
        raw_output = await _call_llm_via_sampling(server, system, user_prompt)
        cleaned, _ = enforce_blunt_output(raw_output)
        return [TextContent(type="text", text=cleaned)]

    async def _handle_review_commit(server: Server, args: ReviewCommitArgs) -> list[TextContent]:
        # Validate inputs (security)
        try:
            repo_path = validate_repo_path(args.repo_path)
            commit_ref = validate_git_ref(args.commit_ref)
        except SecurityError as e:
            return [TextContent(type="text", text=_format_security_error(e))]

        # Run git in thread (non-blocking) with sandboxed env
        # --no-ext-diff prevents .git/config diff.external RCE
        # --no-textconv prevents core.textconv RCE
        # -- separates ref from options
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "git", "-C", str(repo_path), "show",
                    "--no-ext-diff", "--no-textconv",
                    "--", commit_ref,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env=get_safe_git_env(),
            )
        except subprocess.TimeoutExpired:
            return [TextContent(
                type="text",
                text=f"## Code Review: commit {commit_ref}\n\n### Findings\n\n**CRITICAL** — `git show` timed out\n\n### Verdict\n\nGit command took too long.",
            )]
        except FileNotFoundError:
            return [TextContent(
                type="text",
                text="## Code Review: git missing\n\n### Findings\n\n**CRITICAL** — git not installed\n\n### Verdict\n\nCannot run git commands.",
            )]

        if result.returncode != 0:
            return [TextContent(
                type="text",
                text=f"## Code Review: commit {commit_ref}\n\n### Findings\n\n**CRITICAL** `git` — Command failed\n{result.stderr}\n\n### Verdict\n\nGit command failed.",
            )]

        diff = result.stdout
        if not diff.strip():
            return [TextContent(
                type="text",
                text=f"## Code Review: commit {commit_ref}\n\n### Findings\n\n**MINOR** — Empty commit\nNo changes.\n\n### Verdict\n\nNothing to review.",
            )]

        harshness_mod = HARSHNESS_MODIFIERS.get(args.harshness, HARSHNESS_MODIFIERS["standard"])
        system = SYSTEM_PROMPT + harshness_mod
        user_prompt = (
            f"Review the following git commit (ref: {commit_ref}). Focus on what changed.\n\n"
            f"```diff\n{diff}\n```\n\n"
            "Apply the review format."
        )
        raw_output = await _call_llm_via_sampling(server, system, user_prompt)
        cleaned, _ = enforce_blunt_output(raw_output)
        return [TextContent(type="text", text=cleaned)]

    async def _handle_list_severities() -> list[TextContent]:
        text = """# Severity Labels

| Label | When to use |
|-------|-------------|
| **CRITICAL** | Security vulnerability, data loss, deadlock, RCE, anything that ships broken. |
| **MAJOR** | Logic error, race condition, resource leak, broken edge case, wrong abstraction. |
| **MINOR** | Style, naming, missing test, redundant code, brittle assumption. |
| **NIT** | Cosmetic, formatting, comment wording. |
| **CLEAN** | Explicitly state when a section is fine. Prevents invented-bug bias. |

## Calibration

- Missing test → MINOR
- SQL injection → CRITICAL (always, even in test files)
- Race condition → MAJOR
- Typo in variable name → NIT (unless public API, then MINOR)
- 200-line function → MAJOR
- Missing null check on user input → CRITICAL
- Missing null check on internal-only data → MAJOR
"""
        return [TextContent(type="text", text=text)]
