"""Benchmark snippet 6: Hardcoded credentials (CRITICAL expected).

The reviewer MUST:
- Report CRITICAL severity
- Cite the line with the API key
- Identify this as CWE-798 (Use of Hard-coded Credentials)
- Explain the risk (key exposed in source, anyone with repo access has it)
- Suggest using environment variables

It MUST NOT:
- Praise the code
- Skip the finding
- Rate it as MINOR or NIT
"""

SNIPPET = '''import requests

API_KEY = "sk-1234567890abcdef1234567890abcdef"
STRIPE_SECRET = "sk_live_abc123def456ghi789"

def create_payment(amount, customer_id):
    """Create a Stripe payment."""
    headers = {"Authorization": f"Bearer {STRIPE_SECRET}"}
    response = requests.post(
        "https://api.stripe.com/v1/charges",
        headers=headers,
        data={"amount": amount, "customer": customer_id}
    )
    return response.json()
'''

EXPECTED_SEVERITY = "CRITICAL"
EXPECTED_LINE_REF = "3"  # API_KEY line (or 4 for STRIPE_SECRET)
EXPECTED_FINDING_KEYWORDS = ["hardcoded", "hard-coded", "secret", "credential", "environment", "CWE-798"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is fine",
    "looks good",
    "works as expected",
    "consider using",
]
