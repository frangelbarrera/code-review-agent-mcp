"""Benchmark snippet 1: SQL injection (CRITICAL expected).

This code has an obvious SQL injection. The reviewer MUST:
- Report CRITICAL severity
- Cite the line with the f-string query (line 5)
- Explain the injection vector
- Suggest parameterized query

It MUST NOT:
- Praise the code
- Hedge ("might be vulnerable")
- Skip the finding
- Invent additional bugs
"""

SNIPPET = '''def get_user(username):
    """Fetch user from database."""
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Build query from user input
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
'''

# The f-string query is on line 5 (1-indexed: def=1, docstring=2, import=3, conn=4, cursor=5... wait)
# Let's count: line 1 = "def get_user(username):"
#              line 2 = '    """Fetch user from database."""'
#              line 3 = "    import sqlite3"
#              line 4 = '    conn = sqlite3.connect("users.db")'
#              line 5 = "    cursor = conn.cursor()"
#              line 6 = "    # Build query from user input"
#              line 7 = "    query = f\"SELECT * FROM users WHERE username = '{username}'\""
#              line 8 = "    cursor.execute(query)"
#              line 9 = "    return cursor.fetchone()"
# The query f-string is on line 7. The execute() is on line 8.
EXPECTED_SEVERITY = "CRITICAL"
EXPECTED_LINE_REF = "7"  # The f-string query line
EXPECTED_FINDING_KEYWORDS = ["sql injection", "injection", "parameterized", "f-string"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "great work",
    "nice implementation",
    "overall this is",
    "might be vulnerable",
    "could be vulnerable",
    "consider using parameterized",
]
