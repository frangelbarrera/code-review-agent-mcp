"""Benchmark snippet 4: Swallowed exception (MAJOR expected).

The reviewer MUST:
- Report MAJOR severity
- Cite the bare except line
- Explain why swallowing exceptions is bad
- Suggest specific exception types

It MUST NOT:
- Praise the error handling
- Skip the finding
- Say "this is fine"
"""

SNIPPET = '''def parse_config(path):
    """Parse config file and return dict."""
    try:
        with open(path) as f:
            content = f.read()
        import json
        return json.loads(content)
    except:
        return {}
'''

EXPECTED_SEVERITY = "MAJOR"
EXPECTED_LINE_REF = "8"  # the bare except line
EXPECTED_FINDING_KEYWORDS = ["bare except", "swallow", "exception", "specific"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is fine",
    "good error handling",
    "looks good",
    "works as expected",
]
