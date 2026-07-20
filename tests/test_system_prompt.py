"""Tests for the system prompt and prompt construction."""

import pytest

from code_review_agent.prompts.system_prompt import (
    SYSTEM_PROMPT,
    BANNED_PHRASES,
    GOOD_PHRASES,
)
from code_review_agent.tools.review import (
    _detect_language,
    _line_number_code,
    _build_review_prompt,
    HARSHNESS_MODIFIERS,
)


class TestSystemPrompt:
    """Test the system prompt content."""

    def test_prompt_is_substantial(self):
        """System prompt should be substantial (not a one-liner)."""
        assert len(SYSTEM_PROMPT) > 2000
        assert len(SYSTEM_PROMPT.split()) > 300

    def test_prompt_contains_core_principles(self):
        """Prompt must contain the core principles."""
        assert "Code, not coder" in SYSTEM_PROMPT
        assert "Verdict first" in SYSTEM_PROMPT
        assert "severity" in SYSTEM_PROMPT.lower()
        assert "line" in SYSTEM_PROMPT.lower()

    def test_prompt_contains_severity_labels(self):
        """All severity labels must be defined."""
        for label in ["CRITICAL", "MAJOR", "MINOR", "NIT", "CLEAN"]:
            assert label in SYSTEM_PROMPT

    def test_prompt_contains_anti_patterns(self):
        """Anti-patterns section must exist."""
        assert "Anti-patterns" in SYSTEM_PROMPT or "anti-pattern" in SYSTEM_PROMPT.lower()
        assert "hallucinated" in SYSTEM_PROMPT.lower() or "hallucin" in SYSTEM_PROMPT.lower()

    def test_banned_phrases_not_empty(self):
        """Banned phrases list should not be empty."""
        assert len(BANNED_PHRASES) > 10

    def test_banned_phrases_are_lowercase(self):
        """Banned phrases should be stored as-is (regex is case-insensitive)."""
        # Just check they're strings
        for phrase in BANNED_PHRASES:
            assert isinstance(phrase, str)
            assert len(phrase) > 2

    def test_good_phrases_present(self):
        """Good phrases (signals of blunt review) should be present."""
        assert "CRITICAL" in GOOD_PHRASES
        assert "MAJOR" in GOOD_PHRASES
        assert "Ship it." in GOOD_PHRASES  # Note: with period


class TestHarshnessModifiers:
    """Test harshness level modifiers."""

    def test_all_four_levels_present(self):
        """All four harshness levels must be defined."""
        for level in ["gentle", "standard", "brutal", "kernel-maintainer"]:
            assert level in HARSHNESS_MODIFIERS

    def test_modifiers_are_non_empty(self):
        """Each modifier should add content."""
        for level, mod in HARSHNESS_MODIFIERS.items():
            assert len(mod) > 10


class TestLanguageDetection:
    """Test the language detection heuristic."""

    def test_detect_python(self):
        assert _detect_language("def foo():\n    pass") == "python"
        assert _detect_language("import os\nprint('hi')") == "python"

    def test_detect_javascript(self):
        assert _detect_language("function foo() { return 1; }") == "javascript"
        assert _detect_language("const x = 1;") == "javascript"

    def test_detect_c(self):
        assert _detect_language("#include <stdio.h>\nint main() {}") == "c"

    def test_detect_unknown(self):
        assert _detect_language("just some text") == "unknown"
        assert _detect_language("") == "unknown"


class TestLineNumbering:
    """Test the line numbering function."""

    def test_adds_line_numbers(self):
        code = "line1\nline2\nline3"
        numbered = _line_number_code(code)
        assert "1" in numbered
        assert "2" in numbered
        assert "3" in numbered
        assert "line1" in numbered

    def test_handles_empty_code(self):
        numbered = _line_number_code("")
        assert numbered == ""


class TestBuildReviewPrompt:
    """Test the review prompt builder."""

    def test_includes_code(self):
        prompt = _build_review_prompt("print('hi')", "python", "", "standard", "test.py")
        assert "print('hi')" in prompt

    def test_includes_line_numbers(self):
        prompt = _build_review_prompt("print('hi')", "python", "", "standard", "test.py")
        assert "1" in prompt  # line number

    def test_includes_context_when_provided(self):
        prompt = _build_review_prompt("x = 1", "python", "This is a config parser", "standard", "test.py")
        assert "config parser" in prompt

    def test_omits_context_section_when_empty(self):
        prompt = _build_review_prompt("x = 1", "python", "", "standard", "test.py")
        assert "Context:" not in prompt

    def test_includes_source_label(self):
        prompt = _build_review_prompt("x = 1", "python", "", "standard", "myfile.py")
        assert "myfile.py" in prompt
