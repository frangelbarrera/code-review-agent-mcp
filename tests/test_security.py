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

    @pytest.mark.parametrize("ref", [
        "HEAD:creds.txt",
        "main:secret.txt",
        "HEAD~5:deleted/file.txt",
        "abc1234:config/database.yml",
        "refs/heads/main:src/keys.py",
    ])
    def test_rejects_treeish_colon_path(self, ref):
        """The <treeish>:<path> syntax lets callers exfiltrate arbitrary
        files from git history via ``git show``. It must be rejected.
        """
        with pytest.raises(SecurityError, match="invalid characters"):
            validate_git_ref(ref)


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

    # Component-aware matching: legitimate paths that previously matched
    # sensitive patterns via substring must now be accepted.
    def test_legit_etc_passwd_subdir_passes(self, monkeypatch, tmp_path):
        """A file named 'passwd.py' under a local 'etc/' directory must NOT
        match the '/etc/passwd' sensitive pattern (substring matching
        produced this false positive)."""
        legit = tmp_path / "tests" / "etc" / "passwd.py"
        legit.parent.mkdir(parents=True)
        legit.write_text("x = 1\n")
        monkeypatch.chdir(tmp_path)
        assert validate_file_path(str(legit)) == legit.resolve()

    def test_legit_env_example_passes(self, monkeypatch, tmp_path):
        """A file named '.env.example' must NOT match the '/.env' pattern."""
        legit = tmp_path / "app" / ".env.example"
        legit.parent.mkdir(parents=True)
        legit.write_text("EXAMPLE=1\n")
        monkeypatch.chdir(tmp_path)
        assert validate_file_path(str(legit)) == legit.resolve()

    def test_legit_proc_subdir_passes(self, monkeypatch, tmp_path):
        """A 'proc' directory inside the sandbox must NOT match '/proc/'."""
        legit = tmp_path / "docs" / "proc" / "info.md"
        legit.parent.mkdir(parents=True)
        legit.write_text("# Process docs\n")
        monkeypatch.chdir(tmp_path)
        assert validate_file_path(str(legit)) == legit.resolve()

    def test_legit_ssh_readme_passes(self, monkeypatch, tmp_path):
        """A README inside a local 'ssh' directory must NOT match '/.ssh/'
        (which only matches the dotfile component '.ssh')."""
        legit = tmp_path / "src" / "ssh" / "README.md"
        legit.parent.mkdir(parents=True)
        legit.write_text("# SSH docs\n")
        monkeypatch.chdir(tmp_path)
        assert validate_file_path(str(legit)) == legit.resolve()

    def test_real_dotenv_still_blocked(self, monkeypatch, tmp_path):
        """An actual '.env' file must still be rejected."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=1\n")
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SecurityError, match="sensitive"):
            validate_file_path(str(env_file))

    def test_real_ssh_dir_still_blocked(self, monkeypatch, tmp_path):
        """An actual '.ssh/id_rsa' file must still be rejected."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key = ssh_dir / "id_rsa"
        key.write_text("PRIVATE")
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SecurityError, match="sensitive"):
            validate_file_path(str(key))


class TestReadFileToctouSafe:
    """Verify the TOCTOU-safe read helper used by review_file.

    These tests exercise the os.open(O_NOFOLLOW) + os.fstat + os.fdopen
    path directly, without spinning up a full MCP session.
    """

    def _read_safe(self, file_path):
        """Mirror of the _read_safe inner function in review.py."""
        import stat as _stat
        fd = None
        try:
            fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            raise PermissionError(str(e)) from e
        try:
            st = os.fstat(fd)
            if not _stat.S_ISREG(st.st_mode):
                raise OSError("Not a regular file after open")
            if st.st_size > MAX_FILE_SIZE:
                raise OSError(f"File too large after open: {st.st_size}")
            f = os.fdopen(fd, "r", encoding="utf-8", errors="replace")
            fd = None
            try:
                return f.read()
            finally:
                f.close()
        finally:
            if fd is not None:
                os.close(fd)

    def test_reads_regular_file(self, tmp_path):
        f = tmp_path / "x.py"
        f.write_text("print('hi')\n")
        assert self._read_safe(f) == "print('hi')\n"

    def test_rejects_symlink(self, tmp_path):
        """O_NOFOLLOW must reject any symlink, even inside the sandbox."""
        target = tmp_path / "target.txt"
        target.write_text("secret\n")
        link = tmp_path / "link.py"
        os.symlink(target, link)
        with pytest.raises(PermissionError):
            self._read_safe(link)

    def test_rejects_directory(self, tmp_path):
        """Opening a directory must fail (or be rejected by fstat)."""
        d = tmp_path / "subdir"
        d.mkdir()
        # On Linux, opening a directory with O_RDONLY succeeds but fstat
        # identifies it as S_IFDIR, so the helper must reject it.
        try:
            with pytest.raises(OSError):
                self._read_safe(d)
        except PermissionError:
            # Some kernels refuse to open dirs even with O_RDONLY; that's
            # also acceptable.
            pass


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

    def test_rejects_git_symlink_outside_cwd(self, monkeypatch, tmp_path):
        """A .git symlink pointing to a repo outside the sandbox must be
        rejected. Otherwise 'git -C <repo>' operates on the target repo's
        objects, leaking commits the caller cannot access directly.
        """
        import os

        # Target repo lives OUTSIDE the sandbox cwd
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        target_repo = tmp_path / "target_repo"
        target_repo.mkdir()
        (target_repo / ".git").mkdir()

        # evil_repo lives inside the sandbox but its .git is a symlink
        # to target_repo/.git
        evil_repo = sandbox / "evil_repo"
        evil_repo.mkdir()
        os.symlink(target_repo / ".git", evil_repo / ".git")

        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(sandbox)

        with pytest.raises(SecurityError, match=r"\.git symlink"):
            validate_repo_path(str(evil_repo))

    def test_allows_git_symlink_inside_cwd(self, monkeypatch, tmp_path):
        """A .git symlink that stays inside the sandbox is permitted."""
        import os

        # Both repos live inside the sandbox
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        target_repo = sandbox / "target_repo"
        target_repo.mkdir()
        (target_repo / ".git").mkdir()

        evil_repo = sandbox / "evil_repo"
        evil_repo.mkdir()
        os.symlink(target_repo / ".git", evil_repo / ".git")

        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(sandbox)

        result = validate_repo_path(str(evil_repo))
        assert result == evil_repo.resolve()

    def test_rejects_gitfile_outside_cwd(self, monkeypatch, tmp_path):
        """A .git gitfile whose 'gitdir:' points outside the sandbox must be
        rejected. Git follows gitfiles just like symlinks, so the same
        exfiltration vector applies.
        """
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        target_repo = tmp_path / "target_repo"
        target_repo.mkdir()
        (target_repo / ".git").mkdir()

        evil_repo = sandbox / "evil_repo"
        evil_repo.mkdir()
        (evil_repo / ".git").write_text(f"gitdir: {target_repo / '.git'}\n")

        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(sandbox)

        with pytest.raises(SecurityError, match=r"gitfile"):
            validate_repo_path(str(evil_repo))

    def test_allows_gitfile_inside_cwd(self, monkeypatch, tmp_path):
        """A .git gitfile pointing to a path inside the sandbox is permitted."""
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        target_repo = sandbox / "target_repo"
        target_repo.mkdir()
        (target_repo / ".git").mkdir()

        evil_repo = sandbox / "evil_repo"
        evil_repo.mkdir()
        (evil_repo / ".git").write_text(f"gitdir: {target_repo / '.git'}\n")

        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(sandbox)

        result = validate_repo_path(str(evil_repo))
        assert result == evil_repo.resolve()

    def test_allows_regular_gitfile_without_gitdir(self, monkeypatch, tmp_path):
        """A .git file that is not a gitfile (no 'gitdir:' prefix) must not
        trigger the gitfile sandbox check. The validator should accept it
        (it's a regular file matching the existing existence check) without
        raising a symlink/gitfile SecurityError.
        """
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        evil_repo = sandbox / "evil_repo"
        evil_repo.mkdir()
        (evil_repo / ".git").write_text("random content\n")

        monkeypatch.delenv("BLUNT_REVIEW_ALLOW_ABSOLUTE", raising=False)
        monkeypatch.chdir(sandbox)

        # Must NOT raise a symlink or gitfile SecurityError. (It may pass
        # validation entirely; downstream 'git -C' will fail at runtime if
        # the file isn't a real gitfile, which is acceptable.)
        try:
            result = validate_repo_path(str(evil_repo))
            assert result == evil_repo.resolve()
        except SecurityError as e:
            # If a SecurityError is raised, it must not be the symlink/gitfile one
            msg = str(e)
            assert "symlink" not in msg.lower()
            assert "gitfile" not in msg.lower()


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
