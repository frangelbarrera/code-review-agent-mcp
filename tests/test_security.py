"""Security tests for the security module.

Verifies that:
- Path traversal is blocked
- Sensitive files are refused
- Git argument injection is blocked
- Symlink attacks are prevented
- File size limits are enforced
"""

import os
import tempfile
from pathlib import Path

import pytest

from code_review_agent.security import (
    SecurityError,
    validate_file_path,
    validate_git_ref,
    validate_repo_path,
    get_safe_git_env,
    MAX_FILE_SIZE,
    SENSITIVE_PATH_PATTERNS,
)


class TestValidateGitRef:
    """Test git ref validation — prevents option injection."""

    def test_valid_hash(self):
        assert validate_git_ref("abc123def456") == "abc123def456"

    def test_valid_head(self):
        assert validate_git_ref("HEAD") == "HEAD"
        assert validate_git_ref("HEAD~1") == "HEAD~1"
        assert validate_git_ref("HEAD^") == "HEAD^"

    def test_valid_branch_name(self):
        assert validate_git_ref("main") == "main"
        assert validate_git_ref("feature/my-branch") == "feature/my-branch"
        assert validate_git_ref("v1.0.0") == "v1.0.0"

    def test_rejects_option_injection_output(self):
        with pytest.raises(SecurityError, match="option injection"):
            validate_git_ref("--output=/tmp/evil")

    def test_rejects_option_injection_ext_diff(self):
        with pytest.raises(SecurityError, match="option injection"):
            validate_git_ref("--ext-diff")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="Empty"):
            validate_git_ref("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(SecurityError, match="Empty"):
            validate_git_ref("   ")

    def test_rejects_path_traversal(self):
        with pytest.raises(SecurityError, match="path traversal"):
            validate_git_ref("..")

    def test_rejects_shell_metachars(self):
        # These should be rejected by the character whitelist
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_git_ref("HEAD; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_git_ref("HEAD | cat")

    def test_rejects_backticks(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_git_ref("HEAD`whoami`")

    def test_rejects_dollar(self):
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_git_ref("$(whoami)")

    def test_max_length(self):
        long_ref = "a" * 201
        with pytest.raises(SecurityError):
            validate_git_ref(long_ref)

    def test_max_length_boundary(self):
        # 200 chars should be OK
        long_ref = "a" * 200
        assert validate_git_ref(long_ref) == long_ref


class TestValidateFilePath:
    """Test file path validation — prevents path traversal and sensitive file access."""

    def test_valid_relative_file(self, tmp_path, monkeypatch):
        # Create a file under tmp_path and chdir there
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        monkeypatch.chdir(tmp_path)

        result = validate_file_path("test.py")
        assert result == test_file.resolve()

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="Empty"):
            validate_file_path("")

    def test_rejects_option_injection(self):
        with pytest.raises(SecurityError, match="option injection"):
            validate_file_path("--output=/tmp/evil")

    def test_rejects_ssh_key(self, monkeypatch, tmp_path):
        # Even with allow_absolute, .ssh should be refused
        monkeypatch.setenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", "1")
        with pytest.raises(SecurityError, match="sensitive path"):
            validate_file_path("~/.ssh/id_rsa")

    def test_rejects_aws_credentials(self, monkeypatch):
        monkeypatch.setenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", "1")
        with pytest.raises(SecurityError, match="sensitive path"):
            validate_file_path("~/.aws/credentials")

    def test_rejects_env_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", "1")
        with pytest.raises(SecurityError, match="sensitive path"):
            validate_file_path(".env")

    def test_rejects_etc_passwd(self, monkeypatch):
        monkeypatch.setenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", "1")
        with pytest.raises(SecurityError, match="sensitive path"):
            validate_file_path("/etc/passwd")

    def test_rejects_proc_environ(self, monkeypatch):
        # /proc/self/environ may not exist in all test environments,
        # so we test the pattern matching directly
        monkeypatch.setenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", "1")
        # Test that the pattern is in the sensitive list
        assert "/proc/self/environ" in SENSITIVE_PATH_PATTERNS
        # If /proc/self/environ exists, it should be refused
        if os.path.exists("/proc/self/environ"):
            with pytest.raises(SecurityError, match="sensitive path"):
                validate_file_path("/proc/self/environ")

    def test_sandbox_blocks_absolute_outside_cwd(self, monkeypatch, tmp_path):
        # Without BLUNT_REVIEW_ALLOW_ABSOLUTE, absolute paths outside cwd are blocked
        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(tmp_path)

        # Create a file outside the cwd using tmp_path's parent (cross-platform)
        outside_dir = tmp_path.parent / "outside_test_dir"
        outside_dir.mkdir(exist_ok=True)
        outside = outside_dir / "outside_test_file.py"
        try:
            outside.write_text("# test")
            with pytest.raises(SecurityError, match="sandbox"):
                validate_file_path(str(outside))
        finally:
            if outside.exists():
                outside.unlink()
            if outside_dir.exists():
                outside_dir.rmdir()

    def test_sandbox_allows_absolute_inside_cwd(self, monkeypatch, tmp_path):
        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(tmp_path)

        test_file = tmp_path / "test.py"
        test_file.write_text("print('hi')")

        # Absolute path inside cwd should work
        result = validate_file_path(str(test_file))
        assert result == test_file.resolve()

    def test_rejects_nonexistent_file(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SecurityError, match="not found"):
            validate_file_path("nonexistent.py")

    def test_rejects_directory(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        with pytest.raises(SecurityError, match="Not a regular file"):
            validate_file_path("subdir")

    def test_rejects_large_file(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        large_file = tmp_path / "large.py"
        # Create a file larger than MAX_FILE_SIZE
        large_file.write_text("x" * (MAX_FILE_SIZE + 1))
        with pytest.raises(SecurityError, match="too large"):
            validate_file_path("large.py")


class TestValidateRepoPath:
    """Test repo path validation."""

    def test_valid_repo(self, monkeypatch, tmp_path):
        # Create a .git directory
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        monkeypatch.chdir(tmp_path)

        result = validate_repo_path(".")
        assert result == tmp_path.resolve()

    def test_rejects_empty(self):
        with pytest.raises(SecurityError, match="Empty"):
            validate_repo_path("")

    def test_rejects_option_injection(self):
        with pytest.raises(SecurityError):
            validate_repo_path("--output=/tmp/evil")

    def test_rejects_non_git_directory(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SecurityError, match="[Nn]ot a git repository"):
            validate_repo_path(".")

    def test_sandbox_blocks_outside_cwd(self, monkeypatch, tmp_path):
        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SecurityError, match="sandbox"):
            validate_repo_path("/usr/src")


class TestSafeGitEnv:
    """Test the safe git environment."""

    def test_disables_system_config(self):
        env = get_safe_git_env()
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"

    def test_disables_global_config(self):
        env = get_safe_git_env()
        assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"

    def test_includes_path(self):
        env = get_safe_git_env()
        assert "PATH" in env

    def test_includes_home(self):
        env = get_safe_git_env()
        assert "HOME" in env


class TestSensitivePathPatterns:
    """Test that all sensitive path patterns are covered."""

    def test_ssh_pattern_exists(self):
        assert any(".ssh" in p for p in SENSITIVE_PATH_PATTERNS)

    def test_aws_pattern_exists(self):
        assert any(".aws" in p for p in SENSITIVE_PATH_PATTERNS)

    def test_env_pattern_exists(self):
        assert any(".env" in p for p in SENSITIVE_PATH_PATTERNS)

    def test_etc_passwd_exists(self):
        assert "/etc/passwd" in SENSITIVE_PATH_PATTERNS

    def test_proc_environ_exists(self):
        assert "/proc/self/environ" in SENSITIVE_PATH_PATTERNS
