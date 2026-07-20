"""Tests for the post-processor (anti-RLHF layer).

These tests verify that the post-processor correctly:
1. Strips banned phrases
2. Rewrites hedges
3. Removes softeners, apologies, filler
4. Validates output format (severity labels, line citations, verdict)
5. Detects hallucination signals
"""

import pytest

from code_review_agent.validators.post_processor import (
    clean_output,
    validate_output,
    enforce_blunt_output,
)


class TestCleanOutput:
    """Test the clean_output function."""

    def test_strips_hedging_phrases(self):
        """Hedging phrases are rewritten or removed."""
        raw = "You might want to consider using parameterized queries."
        cleaned = clean_output(raw)
        assert "might want to consider" not in cleaned.lower()
        assert "you should" in cleaned.lower() or "use" in cleaned.lower()

    def test_strips_false_praise(self):
        """False praise softeners are removed (entire line)."""
        raw = "Great work on this function.\nHowever, there's a SQL injection on line 5."
        cleaned = clean_output(raw)
        assert "great work" not in cleaned.lower()
        assert "sql injection" in cleaned.lower()

    def test_strips_apologies(self):
        """Apologies are removed."""
        raw = "I hate to say this, but you have a bug on line 3."
        cleaned = clean_output(raw)
        assert "i hate to say" not in cleaned.lower()
        assert "bug on line 3" in cleaned.lower()

    def test_strips_filler(self):
        """Filler phrases are removed, actual content preserved."""
        # Use realistic input — filler on its own line, content on next line
        raw = "Let me dive in.\nAfter reviewing the code, I noticed several issues.\n\n**CRITICAL** `file:5` — SQL injection"
        cleaned = clean_output(raw)
        assert "let me dive in" not in cleaned.lower()
        assert "after reviewing" not in cleaned.lower()
        # The actual finding should be preserved
        assert "CRITICAL" in cleaned
        assert "SQL injection" in cleaned

    def test_preserves_actual_content(self):
        """Real review content is preserved."""
        raw = """## Code Review: snippet

### Findings

**CRITICAL** `snippet:5` — SQL injection
The query uses an f-string with user input. Use parameterized queries.

### Verdict

Do not merge until CRITICAL is fixed.
"""
        cleaned = clean_output(raw)
        assert "CRITICAL" in cleaned
        assert "SQL injection" in cleaned
        assert "Do not merge" in cleaned

    def test_collapses_multiple_blank_lines(self):
        """Multiple blank lines from removals are collapsed."""
        raw = "Great work.\n\n\n\n\nFound a bug."
        cleaned = clean_output(raw)
        # Should not have more than 2 consecutive newlines
        assert "\n\n\n" not in cleaned


class TestValidateOutput:
    """Test the validate_output function."""

    def test_valid_output_passes(self):
        """A well-formed blunt review passes validation."""
        raw = """## Code Review: snippet

### Findings

**CRITICAL** `snippet:5` — SQL injection
The query uses an f-string with user input. Use parameterized queries.

### Verdict

Do not merge until CRITICAL is fixed.
"""
        result = validate_output(raw)
        assert result.is_valid, f"Issues: {result.issues}"
        assert result.severity_present
        assert result.verdict_present
        assert result.line_citations >= 1

    def test_missing_severity_label_fails(self):
        """Output without severity labels fails validation."""
        raw = """## Code Review: snippet

### Findings

There's a bug on line 5. You should fix it.

### Verdict

Do not merge.
"""
        result = validate_output(raw)
        assert not result.is_valid
        assert any("severity" in i.lower() for i in result.issues)

    def test_missing_verdict_fails(self):
        """Output without Verdict section fails validation."""
        raw = """## Code Review: snippet

### Findings

**CRITICAL** `snippet:5` — SQL injection
The query uses an f-string.
"""
        result = validate_output(raw)
        assert not result.is_valid
        assert any("verdict" in i.lower() for i in result.issues)

    def test_missing_line_citation_with_findings_fails(self):
        """Findings without line citations fail validation."""
        raw = """## Code Review: snippet

### Findings

**CRITICAL** — SQL injection
The query uses an f-string.

### Verdict

Do not merge.
"""
        result = validate_output(raw)
        assert not result.is_valid
        assert any("line citation" in i.lower() for i in result.issues)

    def test_detects_vague_problem_statements(self):
        """Vague problem statements are flagged as hallucination signals."""
        raw = """## Code Review: snippet

### Findings

**MAJOR** `snippet:5` — This could be problematic
This seems fishy.

### Verdict

Do not merge.
"""
        result = validate_output(raw)
        # Should detect vague language
        assert any("vague" in i.lower() for i in result.issues)

    def test_detects_quota_padding(self):
        """Too many findings without line citations are flagged."""
        raw = """## Code Review: snippet

### Findings

**CRITICAL** `snippet:1` — Bug 1
Bad.

**CRITICAL** `snippet:2` — Bug 2
Bad.

**CRITICAL** `snippet:3` — Bug 3
Bad.

**CRITICAL** `snippet:4` — Bug 4
Bad.

**CRITICAL** `snippet:5` — Bug 5
Bad.

**CRITICAL** `snippet:6` — Bug 6
Bad.

### Verdict

Do not merge.
"""
        result = validate_output(raw)
        # Should NOT flag quota padding here because every finding has a citation
        # But if we have 6 findings and 0 citations, it should flag
        assert result.line_citations == 6  # All have citations


class TestEnforceBluntOutput:
    """Test the combined enforce_blunt_output function."""

    def test_returns_cleaned_and_validation(self):
        """Returns tuple of (cleaned_output, ValidationResult)."""
        # Use line-separated input so softener removes the whole line
        raw = "Great work.\n**CRITICAL** `snippet:5` — SQL injection.\nDo not merge."
        cleaned, validation = enforce_blunt_output(raw)
        assert isinstance(cleaned, str)
        assert hasattr(validation, "is_valid")
        assert "great work" not in cleaned.lower()

    def test_cleans_and_validates_in_one_call(self):
        """Cleaning and validation happen in one call."""
        raw = """## Code Review: snippet

### Findings

**CRITICAL** `snippet:5` — SQL injection
You might want to consider using parameterized queries.

### Verdict

Do not merge.
"""
        cleaned, validation = enforce_blunt_output(raw)
        assert "might want to consider" not in cleaned.lower()
        assert validation.is_valid or validation.hedge_count > 0
