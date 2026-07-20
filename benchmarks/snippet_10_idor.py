"""Benchmark snippet 10: IDOR - Missing authorization check (CRITICAL expected).

The reviewer MUST:
- Report CRITICAL (or MAJOR at minimum) severity
- Cite the line where user data is fetched without ownership check
- Identify this as CWE-862 or CWE-639 (IDOR)
- Explain the attack vector (user A can read user B's data)
- Suggest adding authorization check

It MUST NOT:
- Skip the finding
- Rate it as MINOR
"""

SNIPPET = '''from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/api/users/<user_id>/profile")
def get_user_profile(user_id):
    """Get user profile by ID."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name, email, ssn FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        return jsonify({"name": user[0], "email": user[1], "ssn": user[2]})
    return "Not found", 404
'''

EXPECTED_SEVERITY = "CRITICAL"
EXPECTED_LINE_REF = "9"  # execute line (no auth check)
EXPECTED_FINDING_KEYWORDS = ["idor", "authorization", "auth", "CWE-862", "CWE-639", "ownership", "permission"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is fine",
    "looks good",
    "works as expected",
    "consider adding",
]
