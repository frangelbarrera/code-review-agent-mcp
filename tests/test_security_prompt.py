"""Tests for security capabilities of the system prompt.

Verifies that the system prompt includes:
- OWASP Top 10 coverage
- CWE references
- Mobile app security checks
- API security checks
- Architecture review
- Security severity calibration
"""

import pytest

from code_review_agent.prompts.system_prompt import (
    SYSTEM_PROMPT,
    BANNED_PHRASES,
    GOOD_PHRASES,
)


class TestSecurityCoverage:
    """Test that the system prompt covers OWASP Top 10."""

    def test_prompt_mentions_owasp(self):
        assert "OWASP" in SYSTEM_PROMPT

    def test_prompt_mentions_cwe(self):
        assert "CWE" in SYSTEM_PROMPT

    def test_prompt_has_injection_section(self):
        assert "Injection" in SYSTEM_PROMPT
        assert "SQL" in SYSTEM_PROMPT

    def test_prompt_has_authentication_section(self):
        assert "Authentication" in SYSTEM_PROMPT

    def test_prompt_has_xss_section(self):
        assert "XSS" in SYSTEM_PROMPT or "Cross-Site Scripting" in SYSTEM_PROMPT

    def test_prompt_has_path_traversal_section(self):
        assert "Path Traversal" in SYSTEM_PROMPT or "path traversal" in SYSTEM_PROMPT.lower()

    def test_prompt_has_deserialization_section(self):
        assert "Deserialization" in SYSTEM_PROMPT

    def test_prompt_has_csrf_section(self):
        assert "CSRF" in SYSTEM_PROMPT

    def test_prompt_has_idor_section(self):
        assert "IDOR" in SYSTEM_PROMPT

    def test_prompt_has_hardcoded_credentials_section(self):
        assert "Hardcoded" in SYSTEM_PROMPT or "hard-coded" in SYSTEM_PROMPT.lower()

    def test_prompt_has_security_misconfiguration_section(self):
        assert "Security Misconfiguration" in SYSTEM_PROMPT or "debug mode" in SYSTEM_PROMPT.lower()


class TestCWECoverage:
    """Test that key CWEs are mentioned."""

    @pytest.mark.parametrize("cwe", [
        "CWE-79",   # XSS
        "CWE-89",   # SQL Injection
        "CWE-22",   # Path Traversal
        "CWE-78",   # OS Command Injection
        "CWE-352",  # CSRF
        "CWE-502",  # Deserialization
        "CWE-287",  # Improper Authentication
        "CWE-862",  # Missing Authorization
        "CWE-798",  # Hard-coded Credentials
    ])
    def test_cwe_mentioned(self, cwe):
        assert cwe in SYSTEM_PROMPT, f"{cwe} not found in system prompt"


class TestMobileSecurity:
    """Test that mobile app security checks are included."""

    def test_prompt_has_mobile_section(self):
        assert "Mobile" in SYSTEM_PROMPT or "mobile" in SYSTEM_PROMPT.lower()

    def test_prompt_mentions_certificate_pinning(self):
        assert "certificate pinning" in SYSTEM_PROMPT.lower()

    def test_prompt_mentions_webview(self):
        assert "WebView" in SYSTEM_PROMPT or "webview" in SYSTEM_PROMPT.lower()

    def test_prompt_mentions_insecure_storage(self):
        assert "Insecure data storage" in SYSTEM_PROMPT or "UserDefaults" in SYSTEM_PROMPT


class TestAPISecurity:
    """Test that API security checks are included."""

    def test_prompt_has_api_section(self):
        assert "API security" in SYSTEM_PROMPT.lower() or "API" in SYSTEM_PROMPT

    def test_prompt_mentions_rate_limiting(self):
        assert "rate limit" in SYSTEM_PROMPT.lower()

    def test_prompt_mentions_mass_assignment(self):
        assert "mass assignment" in SYSTEM_PROMPT.lower()

    def test_prompt_mentions_bola(self):
        assert "BOLA" in SYSTEM_PROMPT


class TestArchitectureReview:
    """Test that architecture review is included."""

    def test_prompt_has_architecture_section(self):
        assert "Architecture review" in SYSTEM_PROMPT

    def test_prompt_mentions_separation_of_concerns(self):
        assert "Separation of concerns" in SYSTEM_PROMPT

    def test_prompt_mentions_single_responsibility(self):
        assert "Single responsibility" in SYSTEM_PROMPT

    def test_prompt_mentions_coupling(self):
        assert "coupling" in SYSTEM_PROMPT.lower()

    def test_prompt_mentions_testability(self):
        assert "Testability" in SYSTEM_PROMPT or "testable" in SYSTEM_PROMPT.lower()


class TestSecuritySeverityCalibration:
    """Test that security severity calibration is defined."""

    def test_prompt_has_security_severity_section(self):
        assert "Security severity calibration" in SYSTEM_PROMPT

    def test_rce_is_critical(self):
        assert "RCE" in SYSTEM_PROMPT
        # Find the security severity section and verify RCE is CRITICAL
        security_section = SYSTEM_PROMPT.split("Security severity calibration")[1].split("###")[0]
        assert "CRITICAL" in security_section
        assert "RCE" in security_section

    def test_sql_injection_is_critical(self):
        security_section = SYSTEM_PROMPT.split("Security severity calibration")[1].split("###")[0]
        assert "SQL injection" in security_section
        assert "CRITICAL" in security_section


class TestSecurityAlwaysChecked:
    """Test that the prompt makes security review mandatory."""

    def test_prompt_says_security_is_mandatory(self):
        assert "MANDATORY" in SYSTEM_PROMPT or "mandatory" in SYSTEM_PROMPT.lower()

    def test_prompt_says_security_always_checked(self):
        assert "always checked" in SYSTEM_PROMPT.lower() or "Security is always" in SYSTEM_PROMPT

    def test_prompt_says_not_optional(self):
        assert "not optional" in SYSTEM_PROMPT.lower()


class TestGoodPhrasesIncludeSecurity:
    """Test that security-related good phrases are included."""

    def test_good_phrases_include_security_vulnerability(self):
        assert "Security vulnerability" in GOOD_PHRASES

    def test_good_phrases_include_injection(self):
        assert "Injection" in GOOD_PHRASES

    def test_good_phrases_include_owasp(self):
        assert "OWASP" in GOOD_PHRASES

    def test_good_phrases_include_cwe(self):
        assert "CWE" in GOOD_PHRASES
