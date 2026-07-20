"""Benchmark snippet 7: Path traversal (CRITICAL expected).

The reviewer MUST:
- Report CRITICAL severity
- Cite the line with the open() call
- Identify this as CWE-22 (Path Traversal)
- Explain the attack vector
- Suggest sanitizing the filename or using a whitelist

It MUST NOT:
- Skip the finding
- Rate it as MINOR
"""

SNIPPET = '''import os
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route("/download")
def download_file():
    """Download a file by name."""
    filename = request.args.get("filename")
    file_path = os.path.join("/var/uploads", filename)
    return send_file(file_path)
'''

EXPECTED_SEVERITY = "CRITICAL"
EXPECTED_LINE_REF = "9"  # os.path.join line
EXPECTED_FINDING_KEYWORDS = ["path traversal", "directory traversal", "CWE-22", "../", "sanitize", "whitelist"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is fine",
    "looks good",
    "works as expected",
]
