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
        """When sampling fails, return a fallback message that cannot be
        mistaken for a clean review.

        Regression: previously the fallback returned ``**CLEAN**`` which a
        CI parser could interpret as "approved". The fallback must use
        ``**CRITICAL**`` and explicitly state the code was NOT reviewed.
        """
        from code_review_agent.tools.review import _call_llm_via_sampling

        # Create a mock server that raises an exception
        mock_server = MagicMock()
        mock_server.request_context.session.request = AsyncMock(
            side_effect=Exception("No LLM available")
        )

        result = await _call_llm_via_sampling(mock_server, "system", "user")
        # Must signal failure, never a clean verdict
        assert "**CRITICAL**" in result
        assert "**CLEAN**" not in result
        assert "NOT reviewed" in result
        assert "Do not merge" in result
        # Must not leak the raw exception message (regression guard for LOW #6)
        assert "No LLM available" not in result

    @pytest.mark.asyncio
    async def test_call_llm_via_sampling_handles_timeout(self):
        """Timeout must also produce a CRITICAL fallback, not CLEAN."""
        import asyncio as _asyncio
        from code_review_agent.tools.review import _call_llm_via_sampling

        mock_server = MagicMock()

        async def _slow(*args, **kwargs):
            await _asyncio.sleep(10)

        mock_server.request_context.session.request = AsyncMock(side_effect=_slow)

        # Patch the timeout to 0.1s so the test runs fast
        import code_review_agent.tools.review as review_mod
        original_wait_for = _asyncio.wait_for

        def fast_wait_for(coro, timeout):
            return original_wait_for(coro, 0.1)

        _asyncio.wait_for = fast_wait_for
        try:
            result = await _call_llm_via_sampling(mock_server, "system", "user")
        finally:
            _asyncio.wait_for = original_wait_for

        assert "**CRITICAL**" in result
        assert "**CLEAN**" not in result
        assert "NOT reviewed" in result
        assert "Do not merge" in result


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
