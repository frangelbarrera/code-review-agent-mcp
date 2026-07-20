"""Stress tests for the post-processor and validators.

These tests verify performance under load and edge cases.
"""

import time
import pytest

from code_review_agent.validators.post_processor import (
    clean_output,
    validate_output,
    enforce_blunt_output,
)
from code_review_agent.prompts.system_prompt import BANNED_PHRASES


class TestStressPostProcessor:
    """Stress test the post-processor with large inputs and many iterations."""

    def test_large_output_10kb(self):
        """Clean a 10KB output in under 100ms."""
        # Build a 10KB output with many findings
        finding = """**CRITICAL** `file:LINE` — Bug description
This is broken because X. The fix is Y.
"""
        large_output = "## Code Review: large_file\n\n### Findings\n\n"
        for i in range(100):
            large_output += finding.replace("LINE", str(i)) + "\n"
        large_output += "### Verdict\n\nDo not merge.\n"

        start = time.perf_counter()
        cleaned = clean_output(large_output)
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, f"Cleaning took {elapsed:.3f}s, expected <0.1s"
        assert len(cleaned) > 5000  # Content preserved

    def test_many_banned_phrases_in_one_call(self):
        """Clean output with all banned phrases at once."""
        raw = " ".join(BANNED_PHRASES[:20])
        cleaned = clean_output(raw)
        # Most should be removed
        assert len(cleaned) < len(raw)

    def test_repeated_calls_are_fast(self):
        """100 cleaning calls complete in under 2 seconds."""
        raw = "Great work. You might want to consider using parameterized queries. **CRITICAL** `file:5` — SQL injection. Do not merge."

        start = time.perf_counter()
        for _ in range(100):
            clean_output(raw)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"100 calls took {elapsed:.3f}s"

    def test_validation_handles_empty_input(self):
        """Empty input doesn't crash."""
        result = validate_output("")
        assert not result.is_valid
        assert len(result.issues) > 0

    def test_validation_handles_whitespace_only(self):
        """Whitespace-only input doesn't crash."""
        result = validate_output("   \n\n   \t  ")
        assert not result.is_valid

    def test_validation_handles_very_long_line(self):
        """A single 10KB line doesn't crash."""
        long_line = "**CRITICAL** `file:5` — " + "x" * 10000
        result = validate_output(long_line)
        # Should not crash
        assert hasattr(result, "is_valid")

    def test_no_regex_catastrophic_backtracking(self):
        """Verify no ReDoS vulnerability in banned phrase regex."""
        # Craft a potentially malicious input
        evil = "you might want to " + "x" * 1000 + " consider"
        start = time.perf_counter()
        clean_output(evil)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, f"Took {elapsed:.3f}s — possible ReDoS"


class TestStressValidation:
    """Stress test the validation logic."""

    def test_many_findings_all_valid(self):
        """Validate output with 50 valid findings."""
        raw = "## Code Review: test\n\n### Findings\n\n"
        for i in range(50):
            raw += f"**CRITICAL** `file:{i}` — Bug {i}\nFix it.\n\n"
        raw += "### Verdict\n\nDo not merge.\n"

        result = validate_output(raw)
        assert result.severity_present
        assert result.verdict_present
        assert result.line_citations == 50

    def test_quota_padding_detection(self):
        """Detect when there are too many findings without citations."""
        raw = "## Code Review: test\n\n### Findings\n\n"
        for i in range(10):
            # No line citations — just severity labels
            raw += f"**CRITICAL** — Bug {i}\nFix it.\n\n"
        raw += "### Verdict\n\nDo not merge.\n"

        result = validate_output(raw)
        # Should detect quota padding (10 findings, 0 citations)
        assert result.line_citations < 10


class TestEdgeCases:
    """Test edge cases that might break the post-processor."""

    def test_unicode_content(self):
        """Unicode in code review doesn't break cleaning."""
        raw = "Great work. **CRITICAL** `file:5` — Bug with émojis 🐛"
        cleaned = clean_output(raw)
        assert "🐛" in cleaned or "Bug with" in cleaned

    def test_code_blocks_in_review(self):
        """Code blocks in the review are preserved."""
        raw = """## Code Review: test

### Findings

**CRITICAL** `file:5` — SQL injection

```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

Use parameterized queries.

### Verdict

Do not merge.
"""
        cleaned = clean_output(raw)
        assert "```python" in cleaned
        assert "parameterized" in cleaned.lower()

    def test_nested_severity_words(self):
        """Severity words in code context don't confuse the validator."""
        raw = """## Code Review: test

### Findings

**CRITICAL** `file:5` — The CRITICAL section in the code
This references a function called CRITICAL_handler. Fix the bug.

### Verdict

Do not merge.
"""
        result = validate_output(raw)
        # Should still validate correctly
        assert result.severity_present

    def test_markdown_table_in_review(self):
        """Markdown tables in review are preserved."""
        raw = """## Code Review: test

### Findings

| Severity | Line | Issue |
|----------|------|-------|
| CRITICAL | 5 | SQL injection |

### Verdict

Do not merge.
"""
        cleaned = clean_output(raw)
        assert "CRITICAL" in cleaned
        assert "SQL injection" in cleaned
