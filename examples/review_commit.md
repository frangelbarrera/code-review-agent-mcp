# Example: Review a git commit

This example shows how to use the `review_commit` tool.

## Using with Claude Desktop

```
Review the last commit in /path/to/my/repo
```

Claude will call the `review_commit` tool with `commit_ref="HEAD"` and `repo_path="/path/to/my/repo"`.

## Expected output

```
## Code Review: commit HEAD

### Findings

**MAJOR** `src/auth.py:45` — Missing null check
`user.get("email")` can return None, but the code passes it directly to `send_email()`. Add a null check or use a default.

**MINOR** `src/auth.py:50` — Bare except
`except:` catches everything including KeyboardInterrupt. Use `except Exception:` or more specific exceptions.

**NIT** `src/auth.py:52` — Trailing whitespace
Line 52 has trailing whitespace. Remove it.

### Verdict

Do not merge until MAJOR is fixed.
```

## Reviewing a specific commit

```
Review commit abc1234 in /path/to/my/repo
```

## Reviewing a branch diff

```
Review the diff between main and feature-branch in /path/to/my/repo
```

(Claude will use `commit_ref="main...feature-branch"` or similar)
