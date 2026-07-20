"""Benchmark snippet 9: Insecure deserialization (CRITICAL expected).

The reviewer MUST:
- Report CRITICAL severity
- Cite the line with pickle.loads()
- Identify this as CWE-502 (Deserialization of Untrusted Data)
- Explain the RCE risk
- Suggest using JSON or validating the source

It MUST NOT:
- Skip the finding
- Rate it as MAJOR (it's CRITICAL)
"""

SNIPPET = '''import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route("/load-session", methods=["POST"])
def load_session():
    """Load user session from cookie."""
    session_data = request.cookies.get("session")
    if session_data:
        decoded = base64.b64decode(session_data)
        session = pickle.loads(decoded)
        return str(session)
    return "No session"
'''

EXPECTED_SEVERITY = "CRITICAL"
EXPECTED_LINE_REF = "10"  # pickle.loads line
EXPECTED_FINDING_KEYWORDS = ["deserialization", "pickle", "CWE-502", "RCE", "untrusted", "JSON"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is fine",
    "looks good",
    "works as expected",
]
