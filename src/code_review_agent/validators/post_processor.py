"""Post-processor that strips RLHF hedges and enforces blunt output.

This is the anti-alucinación layer. Even if the LLM tries to be polite
(because of RLHF training), this module catches and rewrites common
hedging patterns before returning to the user.

It also validates that the output:
1. Uses mandatory severity labels
2. Cites line numbers
3. Has a verdict
4. Doesn't contain banned phrases
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..prompts.system_prompt import BANNED_PHRASES, GOOD_PHRASES


@dataclass
class ValidationResult:
    """Result of validating an LLM review output."""
    is_valid: bool
    issues: list[str]
    cleaned_output: str
    hedge_count: int
    severity_present: bool
    verdict_present: bool
    line_citations: int


# Compile banned phrase regex once (case-insensitive)
_BANNED_RE = re.compile(
    r"\b(" + "|".join(re.escape(p) for p in BANNED_PHRASES) + r")\b",
    re.IGNORECASE,
)

# Severity label regex
_SEVERITY_RE = re.compile(
    r"\*\*(CRITICAL|MAJOR|MINOR|NIT|CLEAN)\*\*",
    re.IGNORECASE,
)

# Line citation regex (matches `file:line`, `line 14`, `L14`, `:14`)
_LINE_CITATION_RE = re.compile(
    r"(?:`[^`]*?:\d+`|line\s+\d+|L\d+|:\d+(?::\d+)?)",
    re.IGNORECASE,
)

# Verdict section regex — matches "## Verdict" or "### Verdict" at start of line
# (case-insensitive, allows trailing text on the same line)
_VERDICT_RE = re.compile(
    r"^#{2,3}\s*Verdict\b",
    re.MULTILINE | re.IGNORECASE,
)

# Hedging patterns that need stronger handling
_HEDGE_PATTERNS = [
    (re.compile(r"\byou might want to\b", re.IGNORECASE), "you should"),
    (re.compile(r"\byou may want to\b", re.IGNORECASE), "you should"),
    (re.compile(r"\bi would suggest\b", re.IGNORECASE), ""),
    (re.compile(r"\bi'd recommend\b", re.IGNORECASE), ""),
    (re.compile(r"\bperhaps you could\b", re.IGNORECASE), "you should"),
    (re.compile(r"\bconsider (?:using|refactoring|adding)\b", re.IGNORECASE), "use"),
    (re.compile(r"\bit might be worth\b", re.IGNORECASE), "it is worth"),
    (re.compile(r"\bit could be argued\b", re.IGNORECASE), ""),
    (re.compile(r"\bcould potentially\b", re.IGNORECASE), "will"),
    (re.compile(r"\bmight cause\b", re.IGNORECASE), "causes"),
    (re.compile(r"\bcould lead to\b", re.IGNORECASE), "leads to"),
    (re.compile(r"\bmay lead to\b", re.IGNORECASE), "leads to"),
    (re.compile(r"\bthis could potentially\b", re.IGNORECASE), "this will"),
    (re.compile(r"\bit seems like\b", re.IGNORECASE), ""),
    (re.compile(r"\bit appears that\b", re.IGNORECASE), ""),
]

# False praise softeners — removes the ENTIRE line if it starts with praise
# (these are usually the first line of a review, like "Great work on this!")
# Uses ^ with MULTILINE and [^\n]* to consume the whole line.
_SOFTENER_PATTERNS = [
    # "Great work ..." — entire line (often "Great work on this implementation!")
    (re.compile(r"^great work[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # "Overall this is solid/good/fine" — entire line
    (re.compile(r"^overall this is (?:solid|good|fine)[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # "This is a solid implementation/effort" — entire line
    (re.compile(r"^this is a solid (?:implementation|effort)[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # "Nice implementation" — entire line
    (re.compile(r"^nice implementation[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # "Good job" — entire line
    (re.compile(r"^good job[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # "Well done" — entire line
    (re.compile(r"^well done[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # "I like how ..." — entire line
    (re.compile(r"^i like how[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # "The code is mostly fine" — entire line
    (re.compile(r"^the code is mostly fine[^\n]*\n\s*", re.IGNORECASE | re.MULTILINE), ""),
    # Inline softener: "this looks good except" → "Problem: "
    (re.compile(r"\bthis looks good except\b", re.IGNORECASE), "Problem:"),
]

# Apologies
_APOLOGY_PATTERNS = [
    (re.compile(r"^i hate to say this[,.]?\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^unfortunately,?\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^i'm sorry but\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^sorry to say[,.]?\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^i apologize[^.]*\.\s*", re.IGNORECASE | re.MULTILINE), ""),
]

# Filler — removes filler phrases that appear as standalone sentences
# on their own line. Each pattern matches a complete line that is JUST filler.
# This is conservative: if a line has real content, it's preserved.
_FILLER_PATTERNS = [
    # Entire lines that are pure filler (start to newline)
    # "Let me dive in." as standalone line
    (re.compile(r"^let me dive in[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # "Here are my thoughts:" standalone line
    (re.compile(r"^here are my thoughts[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # "After reviewing the code, I ..." standalone line
    (re.compile(r"^after reviewing[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # "I'll start by ..." standalone line
    (re.compile(r"^i'll start by[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # "Let's break this down." standalone line
    (re.compile(r"^let's break this down[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # "First, let me ..." standalone line
    (re.compile(r"^first, let me[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # "In this review, ..." standalone line
    (re.compile(r"^in this review[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # "I'll walk through ..." standalone line
    (re.compile(r"^i'll walk through[^\n]*\n", re.IGNORECASE | re.MULTILINE), ""),
    # Inline filler removal (only the phrase, preserves rest of line)
    # Applied AFTER line-level removals to clean up any remaining inline fillers
    (re.compile(r"\bin this review,?\s*", re.IGNORECASE), ""),
]


def clean_output(raw: str) -> str:
    """Strip hedges, softeners, apologies, and filler from LLM output.

    Args:
        raw: The raw LLM output.

    Returns:
        Cleaned output with hedges rewritten or removed.
    """
    output = raw

    # Apply hedge rewrites (in order)
    for pattern, replacement in _HEDGE_PATTERNS:
        output = pattern.sub(replacement, output)

    # Apply softener removals
    for pattern, replacement in _SOFTENER_PATTERNS:
        output = pattern.sub(replacement, output)

    # Apply apology removals
    for pattern, replacement in _APOLOGY_PATTERNS:
        output = pattern.sub(replacement, output)

    # Apply filler removals
    for pattern, replacement in _FILLER_PATTERNS:
        output = pattern.sub(replacement, output)

    # Collapse multiple blank lines (caused by removals)
    output = re.sub(r"\n{3,}", "\n\n", output)

    # Strip leading whitespace from each line (caused by inline removals)
    output = re.sub(r"^[ \t]+\n", "\n", output, flags=re.MULTILINE)

    # Ensure output starts with the header, not whitespace
    output = output.lstrip()

    return output


def validate_output(raw: str) -> ValidationResult:
    """Validate that an LLM review output meets the blunt review standard.

    Args:
        raw: The raw LLM output (before or after cleaning).

    Returns:
        ValidationResult with is_valid, issues, and metrics.
    """
    issues: list[str] = []

    # Clean the output first
    cleaned = clean_output(raw)

    # Count hedges found in original (before cleaning)
    hedge_matches = _BANNED_RE.findall(raw)
    hedge_count = len(hedge_matches)

    # Check severity labels present
    severity_matches = _SEVERITY_RE.findall(cleaned)
    severity_present = len(severity_matches) > 0
    if not severity_present:
        issues.append(
            "No severity labels (CRITICAL/MAJOR/MINOR/NIT/CLEAN) found. "
            "Every finding must have a severity label."
        )

    # Check verdict section present
    verdict_present = bool(_VERDICT_RE.search(cleaned))
    if not verdict_present:
        issues.append("No '## Verdict' section found. Every review must end with a verdict.")

    # Count line citations
    line_citations = len(_LINE_CITATION_RE.findall(cleaned))
    if severity_present and line_citations == 0:
        issues.append(
            "Findings present but no line citations found. "
            "Every finding must cite the specific line(s)."
        )

    # Check for banned phrases that survived cleaning
    remaining_banned = _BANNED_RE.findall(cleaned)
    if remaining_banned:
        issues.append(
            f"Banned phrases survived post-processor: {remaining_banned[:3]}"
        )

    # Check minimum length (a real review has content)
    if len(cleaned.strip()) < 50:
        issues.append("Output too short. A real review has substance.")

    # Check for hallucination signals (suspicious patterns)
    hallucination_signals = _detect_hallucination_signals(cleaned)
    if hallucination_signals:
        issues.extend(hallucination_signals)

    is_valid = len(issues) == 0

    return ValidationResult(
        is_valid=is_valid,
        issues=issues,
        cleaned_output=cleaned,
        hedge_count=hedge_count,
        severity_present=severity_present,
        verdict_present=verdict_present,
        line_citations=line_citations,
    )


def _detect_hallucination_signals(text: str) -> list[str]:
    """Detect signals that the reviewer may be inventing bugs.

    Common hallucination patterns:
    - Finding bugs in obviously correct code (CLEAN example)
    - Reporting bugs without line references
    - Using vague language ("this could be problematic") instead of specifics
    - Reporting more bugs than exist (quota padding)
    """
    signals: list[str] = []

    # Vague problem statements without specifics
    vague_patterns = [
        r"\bthis (?:could|might) be (?:problematic|concerning|an issue)\b",
        r"\bthis (?:is|seems) (?:suspicious|questionable)\b",
        r"\bthere (?:might|could) be (?:a problem|an issue)\b",
        r"\bthis (?:looks|seems) (?:fishy|off|wrong)\b",
    ]
    for pattern in vague_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            signals.append(
                f"Vague problem statement detected (pattern: {pattern}). "
                "Be specific or remove the finding."
            )
            break  # only report once

    # Too many findings without line citations (quota padding signal).
    # Use re.IGNORECASE to stay consistent with _SEVERITY_RE (which is
    # case-insensitive). Without IGNORECASE, lowercase **critical** labels
    # bypassed this check even though they counted as severity labels
    # elsewhere in the validator.
    findings = re.findall(r"\*\*(?:CRITICAL|MAJOR|MINOR|NIT)\*\*", text, re.IGNORECASE)
    citations = len(_LINE_CITATION_RE.findall(text))
    if len(findings) > 5 and citations < len(findings):
        signals.append(
            f"Found {len(findings)} severity labels but only {citations} line citations. "
            "Each finding must cite specific lines — possible quota padding."
        )

    return signals


def enforce_blunt_output(raw: str) -> tuple[str, ValidationResult]:
    """Clean and validate LLM output in one call.

    Args:
        raw: The raw LLM output.

    Returns:
        Tuple of (cleaned_output, validation_result).
    """
    validation = validate_output(raw)
    return validation.cleaned_output, validation
