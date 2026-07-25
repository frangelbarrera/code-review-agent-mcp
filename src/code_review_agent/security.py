"""Security utilities for input validation and sandboxing.

Prevents:
- Path traversal (review_file reading /etc/passwd, ~/.ssh/id_rsa, etc.)
- Git argument injection (commit_ref = "--output=/tmp/evil")
- Command injection via git options (--ext-diff, --output)
- TOCTOU attacks (symlink swap between check and read)
- Resource exhaustion (reading huge files)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

# Maximum file size we'll review (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Sensitive paths that review_file will REFUSE to read
SENSITIVE_PATH_PATTERNS = [
    # System account / shadow databases
    "/etc/passwd",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    # System services that often hold secrets
    "/etc/cron.d/",
    "/etc/crontab",
    "/etc/nginx/",
    "/etc/ssl/",
    "/etc/ssl/private/",
    "/etc/mysql/",
    "/etc/postgresql/",
    "/etc/redis/",
    # User-home dotfiles with credentials or keys
    "/.ssh/",  # SSH keys
    "/.aws/",  # AWS credentials
    "/.config/aws/",
    "/.config/gcloud/",
    "/.config/git/credentials",
    "/.gnupg/",  # GPG keys
    "/.docker/",  # Docker config
    "/.kube/",  # Kubernetes config
    "/.npmrc",  # npm tokens
    "/.pypirc",  # PyPI tokens
    "/.git-credentials",  # Git credentials
    "/.gitconfig",
    "/.env",  # Environment files with secrets
    "/.netrc",  # Netrc with credentials
    "/.bashrc",
    "/.bash_history",
    "/.bash_profile",
    "/.zshrc",
    "/.zsh_history",
    "/.profile",
    "/.pgpass",
    "/.my.cnf",
    "/.terraformrc",
    "/.terraform.d/",
    "/.ansible/",
    # Browser / IDE profiles can contain tokens and history
    "/.mozilla/",
    "/.config/google-chrome/",
    "/.vscode/",
    "/.idea/",
    # Process introspection
    "/proc/self/environ",  # Process environment (self)
    "/proc/self/cmdline",  # Process command line (self)
    "/proc/",  # Any /proc/<PID>/ path (after resolve, /proc/self becomes /proc/<PID>)
    "/sys/",  # Sysfs
]

# Git ref pattern: only safe characters, max 200 chars
# Allows: hex hashes, HEAD, HEAD~1, HEAD^, branch names, tag names, refs/heads/x
# Blocks: anything starting with - (option injection), shell metachars, ..
# Includes ^ for HEAD^ (parent), ~ for HEAD~1 (nth parent)
# ':' is INTENTIONALLY EXCLUDED. Git interprets <treeish>:<path> as
# "retrieve this file from this treeish", which would let callers ask
# review_commit to exfiltrate arbitrary files from git history (e.g.
# HEAD:creds.txt, main:secret.txt, HEAD~5:deleted/file.txt).
_SAFE_GIT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+=~^*-]{0,199}$")


class SecurityError(Exception):
    """Raised when input fails security validation."""
    pass


def validate_file_path(file_path: str) -> Path:
    """Validate and sanitize a file path for review_file.

    Security checks:
    1. Reject empty paths
    2. Reject paths starting with - (option injection)
    3. Expand user (~) and resolve to absolute
    4. Reject sensitive paths (.ssh, .aws, .env, /etc/passwd, etc.)
    5. Reject paths outside the current working directory tree
       (unless explicitly allowed via BLUNT_REVIEW_ALLOW_ABSOLUTE=1)
    6. Reject symlinks pointing outside the allowed root
    7. Reject paths that don't exist or aren't files
    8. Reject files larger than MAX_FILE_SIZE

    Args:
        file_path: The file path to validate.

    Returns:
        Resolved Path object if safe.

    Raises:
        SecurityError: If the path fails any security check.
    """
    if not file_path or not file_path.strip():
        raise SecurityError("Empty file path")

    # Reject option injection
    if file_path.startswith("-"):
        raise SecurityError(f"Path starts with '-' (option injection): {file_path}")

    # Expand user and resolve to absolute
    raw_path = Path(file_path).expanduser()
    try:
        resolved = raw_path.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise SecurityError(f"Cannot resolve path: {e}")

    # Check against sensitive path patterns using component-aware matching.
    # Substring matching ('pattern in resolved_str') produces false positives
    # on legitimate paths like 'tests/etc/passwd.py' (matches '/etc/passwd')
    # or 'app/.env.example' (matches '/.env').
    #
    # Two pattern families exist in SENSITIVE_PATH_PATTERNS:
    #   * Absolute system paths: '/etc/passwd', '/proc/', '/sys/'. These
    #     must match only at the root of the resolved path.
    #   * Home-relative dotfile patterns: '/.ssh/', '/.env', '/.aws/'.
    #     These must match whenever the named dotfile component appears
    #     anywhere in the path (the user's home is just one of several
    #     places these can live).
    resolved_str = str(resolved).replace("\\", "/")
    components = [c for c in resolved_str.split("/") if c]
    for pattern in SENSITIVE_PATH_PATTERNS:
        token = pattern.strip("/")
        if not token:
            continue
        if pattern.startswith("/."):
            # Home-relative dotfile pattern. Match if any path component
            # equals the pattern's token.
            if token in components:
                raise SecurityError(
                    f"Refusing to read sensitive path (matches pattern "
                    f"'{pattern}'): {resolved_str}"
                )
        else:
            # Absolute system path pattern. Match only if the resolved
            # path starts with the pattern (directory prefix) or equals it.
            if resolved_str == pattern.rstrip("/") or resolved_str.startswith(pattern):
                raise SecurityError(
                    f"Refusing to read sensitive path (matches pattern "
                    f"'{pattern}'): {resolved_str}"
                )

    # Sandbox: only allow paths under the current working directory
    # unless explicitly overridden via env var (for power users)
    allow_absolute = os.environ.get("BLUNT_REVIEW_ALLOW_ABSOLUTE", "") == "1"
    if not allow_absolute:
        cwd = Path.cwd().resolve()
        try:
            resolved.relative_to(cwd)
        except ValueError:
            raise SecurityError(
                f"Path outside working directory (sandbox): {resolved}. "
                f"Run from the project root, or set BLUNT_REVIEW_ALLOW_ABSOLUTE=1 "
                f"to allow absolute paths (security risk)."
            )

    # Check existence
    if not resolved.exists():
        raise SecurityError(f"File not found: {resolved}")

    # Check it's a regular file (not a device, socket, etc.)
    if not resolved.is_file():
        raise SecurityError(f"Not a regular file: {resolved}")

    # Reject symlinks pointing outside the sandbox
    if raw_path.is_symlink():
        link_target = raw_path.resolve()
        cwd = Path.cwd().resolve()
        try:
            link_target.relative_to(cwd)
        except ValueError:
            raise SecurityError(
                f"Symlink points outside working directory: {raw_path} -> {link_target}"
            )

    # Check file size
    try:
        size = resolved.stat().st_size
    except OSError as e:
        raise SecurityError(f"Cannot stat file: {e}")

    if size > MAX_FILE_SIZE:
        raise SecurityError(
            f"File too large: {size} bytes (max {MAX_FILE_SIZE} bytes = 10 MB)"
        )

    return resolved


def validate_git_ref(commit_ref: str) -> str:
    """Validate a git commit reference for review_commit.

    Security checks:
    1. Reject empty refs
    2. Reject refs starting with - (option injection)
    3. Only allow safe characters: [A-Za-z0-9._/+=~^-]
       (':' is intentionally excluded — see _SAFE_GIT_REF)
    4. Max 200 characters
    5. Reject refs containing .. (path traversal in git)

    This prevents:
    - `--output=/tmp/evil` (write to arbitrary file)
    - `--ext-diff` (RCE via .git/config diff.external)
    - `HEAD:creds.txt` (file exfiltration from git history)
    - Shell injection (we use shell=False, but defense in depth)

    Args:
        commit_ref: The git reference to validate (hash, HEAD, branch, etc.)

    Returns:
        The validated ref string.

    Raises:
        SecurityError: If the ref fails validation.
    """
    if not commit_ref or not commit_ref.strip():
        raise SecurityError("Empty git ref")

    commit_ref = commit_ref.strip()

    # Reject option injection
    if commit_ref.startswith("-"):
        raise SecurityError(f"Git ref starts with '-' (option injection): {commit_ref}")

    # Reject path traversal
    if ".." in commit_ref:
        raise SecurityError(f"Git ref contains '..' (path traversal): {commit_ref}")

    # Character whitelist
    if not _SAFE_GIT_REF.match(commit_ref):
        raise SecurityError(
            f"Git ref contains invalid characters: {commit_ref!r}. "
            f"Allowed: alphanumeric, . _ / + = ~ ^ -"
        )

    return commit_ref


def validate_repo_path(repo_path: str) -> Path:
    """Validate a git repository path for review_commit.

    Security checks:
    1. Reject empty paths
    2. Reject paths starting with -
    3. Expand and resolve
    4. Sandbox to current working directory (unless BLUNT_REVIEW_ALLOW_ABSOLUTE=1)
    5. Verify .git exists (directory or gitfile)
    6. Reject symlinks pointing outside sandbox

    Args:
        repo_path: Path to the git repository.

    Returns:
        Resolved Path object if safe.

    Raises:
        SecurityError: If the path fails validation.
    """
    if not repo_path or not repo_path.strip():
        raise SecurityError("Empty repo path")

    if repo_path.startswith("-"):
        raise SecurityError(f"Repo path starts with '-': {repo_path}")

    raw_path = Path(repo_path).expanduser()
    try:
        resolved = raw_path.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise SecurityError(f"Cannot resolve repo path: {e}")

    # Sandbox
    allow_absolute = os.environ.get("BLUNT_REVIEW_ALLOW_ABSOLUTE", "") == "1"
    if not allow_absolute:
        cwd = Path.cwd().resolve()
        try:
            resolved.relative_to(cwd)
        except ValueError:
            raise SecurityError(
                f"Repo path outside working directory (sandbox): {resolved}. "
                f"Set BLUNT_REVIEW_ALLOW_ABSOLUTE=1 to allow (security risk)."
            )

    # Check .git exists (directory or gitfile)
    git_dir = resolved / ".git"
    if not git_dir.exists() and not (resolved / ".git").is_file():
        raise SecurityError(f"Not a git repository (no .git found): {resolved}")

    # Reject .git symlinks pointing outside the sandbox.
    # A symlinked .git makes 'git -C <repo>' operate on the TARGET repo's
    # objects, bypassing the sandbox check on the actual git data source.
    # This matters in shared environments where a user has write access to
    # their own directory but not to other repos on the same filesystem.
    if git_dir.is_symlink():
        link_target = git_dir.resolve()
        cwd = Path.cwd().resolve()
        try:
            link_target.relative_to(cwd)
        except ValueError:
            raise SecurityError(
                f".git symlink points outside working directory: "
                f"{git_dir} -> {link_target}"
            )

    # Reject .git gitfiles whose 'gitdir:' target points outside the sandbox.
    # A gitfile is a regular file with a single line like 'gitdir: /path/to/.git'.
    # git follows it just like a symlink, so the same exfiltration vector applies.
    if git_dir.is_file():
        try:
            content = git_dir.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as e:
            raise SecurityError(f"Cannot read .git gitfile: {e}")
        if content.startswith("gitdir:"):
            target_str = content[len("gitdir:"):].strip()
            gitfile_target = Path(target_str)
            if not gitfile_target.is_absolute():
                gitfile_target = (resolved / gitfile_target).resolve()
            else:
                gitfile_target = gitfile_target.resolve()
            cwd = Path.cwd().resolve()
            try:
                gitfile_target.relative_to(cwd)
            except ValueError:
                raise SecurityError(
                    f".git gitfile points outside working directory: "
                    f"{git_dir} -> {gitfile_target}"
                )

    # Reject symlinks pointing outside sandbox
    if raw_path.is_symlink():
        link_target = raw_path.resolve()
        cwd = Path.cwd().resolve()
        try:
            link_target.relative_to(cwd)
        except ValueError:
            raise SecurityError(
                f"Symlink points outside working directory: {raw_path} -> {link_target}"
            )

    return resolved


def get_safe_git_env() -> dict:
    """Return a sanitized environment for git subprocess calls.

    Prevents .git/config attacks (diff.external, core.askpass, etc.)
    by disabling global and system git config. Also clears the
    environment variables that git would otherwise use to invoke
    external helpers (SSH, credential helpers, askpass, proxy). The
    current call sites only run 'git show' against a local ref, so
    none of those helpers are required; clearing them is defense in
    depth in case a future call site triggers network access.

    Returns:
        Environment dict with git config disabled and helper vars
        cleared.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        # Disable global and system git config
        "GIT_CONFIG_NOSYSTEM": "1",  # Ignore /etc/gitconfig
        "GIT_CONFIG_GLOBAL": "/dev/null",  # Ignore ~/.gitconfig + ~/.config/git/config
        # Defense in depth: block network / credential / askpass vectors
        "GIT_SSH_COMMAND": "",
        "GIT_SSH": "",
        "GIT_PROXY_COMMAND": "",
        "GIT_CREDENTIAL_HELPER": "",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_TERMINAL_PROMPT": "0",  # never prompt for credentials
        "GIT_ATTR_NOSYSTEM": "1",    # ignore /etc/gitattributes (filter commands)
    }
    return env
