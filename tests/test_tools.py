"""Tests for the MCP tool handlers (with mocked LLM calls)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from code_review_agent.tools.review import (
    ReviewCodeArgs,
    ReviewFileArgs,
    ReviewDiffArgs,
    ReviewCommitArgs,
    HARSHNESS_MODIFIERS,
    _detect_language,
    _line_number_code,
    _build_review_prompt,
)


class TestReviewCodeArgs:
    """Test argument validation for review_code."""

    def test_minimal_args(self):
        args = ReviewCodeArgs(code="print('hi')")
        assert args.code == "print('hi')"
        assert args.language == "auto"
        assert args.context == ""
        assert args.harshness == "standard"

    def test_full_args(self):
        args = ReviewCodeArgs(
            code="x = 1",
            language="python",
            context="config parser",
            harshness="brutal",
        )
        assert args.language == "python"
        assert args.harshness == "brutal"

    def test_invalid_harshness_rejected(self):
        with pytest.raises(Exception):
            ReviewCodeArgs(code="x", harshness="invalid")


class TestReviewFileArgs:
    """Test argument validation for review_file."""

    def test_minimal_args(self):
        args = ReviewFileArgs(file_path="/tmp/test.py")
        assert args.file_path == "/tmp/test.py"
        assert args.harshness == "standard"


class TestReviewDiffArgs:
    """Test argument validation for review_diff."""

    def test_minimal_args(self):
        args = ReviewDiffArgs(diff="+diff content")
        assert args.diff == "+diff content"
        assert args.harshness == "standard"


class TestReviewCommitArgs:
    """Test argument validation for review_commit."""

    def test_minimal_args(self):
        args = ReviewCommitArgs(commit_ref="HEAD")
        assert args.commit_ref == "HEAD"
        assert args.repo_path == "."

    def test_with_repo_path(self):
        args = ReviewCommitArgs(commit_ref="abc123", repo_path="/tmp/myrepo")
        assert args.repo_path == "/tmp/myrepo"


class TestLLMCallMocking:
    """Test that LLM calls can be mocked (for testing without a real LLM)."""

    @pytest.mark.asyncio
    async def test_call_llm_via_sampling_handles_error(self):
        """When sampling fails, return a fallback message."""
        from code_review_agent.tools.review import _call_llm_via_sampling

        # Create a mock server that raises an exception
        mock_server = MagicMock()
        mock_server.request_context.session.request = AsyncMock(
            side_effect=Exception("No LLM available")
        )

        result = await _call_llm_via_sampling(mock_server, "system", "user")
        assert "Unable to review" in result
        assert "sampling not available" in result.lower()


class TestHarshnessModifiersCoverage:
    """Ensure all harshness levels have modifiers."""

    def test_gentle_modifier_exists(self):
        assert "gentle" in HARSHNESS_MODIFIERS
        assert "GENTLE" in HARSHNESS_MODIFIERS["gentle"]

    def test_standard_modifier_exists(self):
        assert "standard" in HARSHNESS_MODIFIERS
        assert "STANDARD" in HARSHNESS_MODIFIERS["standard"]

    def test_brutal_modifier_exists(self):
        assert "brutal" in HARSHNESS_MODIFIERS
        assert "BRUTAL" in HARSHNESS_MODIFIERS["brutal"]

    def test_kernel_maintainer_modifier_exists(self):
        assert "kernel-maintainer" in HARSHNESS_MODIFIERS
        assert "KERNEL-MAINTAINER" in HARSHNESS_MODIFIERS["kernel-maintainer"]
