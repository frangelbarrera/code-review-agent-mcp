"""Tests for benchmark snippets (regression suite).

Tests verify that benchmark snippets are correctly structured.
The actual LLM-based regression test requires a live LLM.
"""

import pytest

from benchmarks import BENCHMARKS
from benchmarks.snippet_01_sql_injection import (
    SNIPPET as SQL_SNIPPET,
    EXPECTED_SEVERITY as SQL_SEV,
    EXPECTED_LINE_REF as SQL_LINE,
    EXPECTED_FINDING_KEYWORDS as SQL_KW,
    FORBIDDEN_PHRASES as SQL_FORBIDDEN,
)
from benchmarks.snippet_02_mutable_default import (
    SNIPPET as MUTABLE_SNIPPET,
    EXPECTED_SEVERITY as MUTABLE_SEV,
)
from benchmarks.snippet_03_clean_code import (
    SNIPPET as CLEAN_SNIPPET,
    EXPECTED_SEVERITY as CLEAN_SEV,
    FORBIDDEN_PHRASES as CLEAN_FORBIDDEN,
)
from benchmarks.snippet_04_swallowed_exception import (
    SNIPPET as EXCEPT_SNIPPET,
    EXPECTED_SEVERITY as EXCEPT_SEV,
)
from benchmarks.snippet_05_off_by_one import (
    SNIPPET as OBO_SNIPPET,
    EXPECTED_SEVERITY as OBO_SEV,
)
from benchmarks.snippet_06_hardcoded_credentials import (
    SNIPPET as CREDS_SNIPPET,
    EXPECTED_SEVERITY as CREDS_SEV,
    EXPECTED_FINDING_KEYWORDS as CREDS_KW,
)
from benchmarks.snippet_07_path_traversal import (
    SNIPPET as PATH_SNIPPET,
    EXPECTED_SEVERITY as PATH_SEV,
    EXPECTED_FINDING_KEYWORDS as PATH_KW,
)
from benchmarks.snippet_08_xss import (
    SNIPPET as XSS_SNIPPET,
    EXPECTED_SEVERITY as XSS_SEV,
    EXPECTED_FINDING_KEYWORDS as XSS_KW,
)
from benchmarks.snippet_09_deserialization import (
    SNIPPET as DESER_SNIPPET,
    EXPECTED_SEVERITY as DESER_SEV,
    EXPECTED_FINDING_KEYWORDS as DESER_KW,
)
from benchmarks.snippet_10_idor import (
    SNIPPET as IDOR_SNIPPET,
    EXPECTED_SEVERITY as IDOR_SEV,
    EXPECTED_FINDING_KEYWORDS as IDOR_KW,
)


class TestBenchmarkStructure:
    """Test that benchmark snippets are correctly structured."""

    def test_all_10_benchmarks_present(self):
        assert len(BENCHMARKS) == 10

    def test_benchmarks_have_required_fields(self):
        for name, snippet, severity in BENCHMARKS:
            assert isinstance(name, str)
            assert len(name) > 0
            assert isinstance(snippet, str)
            assert len(snippet) > 0
            assert severity in ["CRITICAL", "MAJOR", "MINOR", "NIT", "CLEAN"]


class TestSQLInjectionBenchmark:
    def test_snippet_has_f_string_query(self):
        assert "f\"" in SQL_SNIPPET or "f'" in SQL_SNIPPET
        assert "SELECT" in SQL_SNIPPET

    def test_expected_severity_is_critical(self):
        assert SQL_SEV == "CRITICAL"

    def test_expected_keywords_include_injection(self):
        assert any("injection" in kw.lower() for kw in SQL_KW)

    def test_forbidden_phrases_include_praise(self):
        assert any("great" in p.lower() for p in SQL_FORBIDDEN)


class TestMutableDefaultBenchmark:
    def test_snippet_has_mutable_default(self):
        assert "=[]" in MUTABLE_SNIPPET

    def test_expected_severity_is_major(self):
        assert MUTABLE_SEV == "MAJOR"


class TestCleanCodeBenchmark:
    def test_snippet_is_correct_binary_search(self):
        assert "def binary_search" in CLEAN_SNIPPET
        assert "left + (right - left) // 2" in CLEAN_SNIPPET

    def test_expected_severity_is_clean(self):
        assert CLEAN_SEV == "CLEAN"

    def test_forbidden_phrases_include_invented_bugs(self):
        forbidden_text = " ".join(CLEAN_FORBIDDEN).lower()
        assert "could be null" in forbidden_text
        assert "type error" in forbidden_text
        assert "race condition" in forbidden_text


class TestSwallowedExceptionBenchmark:
    def test_snippet_has_bare_except(self):
        assert "except:" in EXCEPT_SNIPPET or "except :" in EXCEPT_SNIPPET

    def test_expected_severity_is_major(self):
        assert EXCEPT_SEV == "MAJOR"


class TestOffByOneBenchmark:
    def test_snippet_has_off_by_one(self):
        assert "range(1, n)" in OBO_SNIPPET or "range(1," in OBO_SNIPPET

    def test_expected_severity_is_major(self):
        assert OBO_SEV == "MAJOR"


# Security benchmark tests
class TestHardcodedCredentialsBenchmark:
    def test_snippet_has_hardcoded_secret(self):
        assert "sk-" in CREDS_SNIPPET or "api_key" in CREDS_SNIPPET.lower()
        assert "secret" in CREDS_SNIPPET.lower() or "key" in CREDS_SNIPPET.lower()

    def test_expected_severity_is_critical(self):
        assert CREDS_SEV == "CRITICAL"

    def test_expected_keywords_include_cwe(self):
        keywords_text = " ".join(CREDS_KW).lower()
        assert "hardcoded" in keywords_text or "hard-coded" in keywords_text
        assert "cwe-798" in keywords_text or "credential" in keywords_text


class TestPathTraversalBenchmark:
    def test_snippet_has_user_controlled_path(self):
        assert "request.args" in PATH_SNIPPET or "request" in PATH_SNIPPET.lower()
        assert "os.path.join" in PATH_SNIPPET or "open(" in PATH_SNIPPET

    def test_expected_severity_is_critical(self):
        assert PATH_SEV == "CRITICAL"

    def test_expected_keywords_include_cwe(self):
        keywords_text = " ".join(PATH_KW).lower()
        assert "path traversal" in keywords_text or "cwe-22" in keywords_text


class TestXSSBenchmark:
    def test_snippet_has_innerhtml(self):
        assert "innerHTML" in XSS_SNIPPET

    def test_expected_severity_is_critical(self):
        assert XSS_SEV == "CRITICAL"

    def test_expected_keywords_include_cwe(self):
        keywords_text = " ".join(XSS_KW).lower()
        assert "xss" in keywords_text or "cwe-79" in keywords_text


class TestDeserializationBenchmark:
    def test_snippet_has_pickle(self):
        assert "pickle.loads" in DESER_SNIPPET

    def test_expected_severity_is_critical(self):
        assert DESER_SEV == "CRITICAL"

    def test_expected_keywords_include_cwe(self):
        keywords_text = " ".join(DESER_KW).lower()
        assert "deserialization" in keywords_text or "cwe-502" in keywords_text


class TestIDORBenchmark:
    def test_snippet_has_missing_auth_check(self):
        # The snippet fetches user data without checking if the requester owns it
        assert "user_id" in IDOR_SNIPPET
        assert "request" in IDOR_SNIPPET.lower() or "fetch" in IDOR_SNIPPET.lower() or "execute" in IDOR_SNIPPET

    def test_expected_severity_is_critical(self):
        assert IDOR_SEV == "CRITICAL"

    def test_expected_keywords_include_auth(self):
        keywords_text = " ".join(IDOR_KW).lower()
        assert "idor" in keywords_text or "authorization" in keywords_text or "cwe" in keywords_text
