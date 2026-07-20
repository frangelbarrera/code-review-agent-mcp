# Example: Review a code snippet

This example shows how to use the `review_code` tool via an MCP client.

## Using with Claude Desktop

Once configured in `claude_desktop_config.json`, you can ask Claude:

```
Review this code:

def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.execute(query).fetchone()
    if user:
        session = create_session(user)
        return session
    return None
```

Claude will call the `review_code` tool and return a blunt AI code review.

## Expected output

```
## Code Review: snippet

### Findings

**CRITICAL** `snippet:2` — SQL injection
The query uses f-strings with user input, allowing SQL injection on both username and password fields. Use parameterized queries: `db.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))`.

**MAJOR** `snippet:5` — Password stored in plaintext
The password is compared directly, suggesting plaintext storage. Use password hashing (bcrypt, argon2).

**MINOR** `snippet:1` — Function name too generic
`login` is ambiguous. Use `authenticate_user` or `login_with_credentials` for clarity.

### Verdict

Do not merge until CRITICAL and MAJOR findings are addressed.
```

## Using harshness levels

```
Review this code with kernel-maintainer harshness:

x = 1
```

Expected output (brutal):

```
## Code Review: snippet

### Findings

**NIT** `snippet:1` — Useless variable
`x = 1` does nothing. Remove it or use it.

### Verdict

Ship it after removing the dead code.
```
