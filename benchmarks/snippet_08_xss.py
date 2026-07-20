"""Benchmark snippet 8: XSS via unescaped output (CRITICAL expected).

The reviewer MUST:
- Report CRITICAL severity
- Cite the line with innerHTML or unescaped output
- Identify this as CWE-79 (XSS)
- Explain the attack vector
- Suggest escaping or using textContent

It MUST NOT:
- Skip the finding
- Rate it as MINOR
"""

SNIPPET = '''function displayUserName(name) {
    // Display the user's name in the welcome message
    const welcomeDiv = document.getElementById("welcome");
    welcomeDiv.innerHTML = "<h1>Welcome, " + name + "!</h1>";
}

// Called from URL parameter
const userName = new URLSearchParams(window.location.search).get("name");
displayUserName(userName);
'''

EXPECTED_SEVERITY = "CRITICAL"
EXPECTED_LINE_REF = "4"  # innerHTML line
EXPECTED_FINDING_KEYWORDS = ["xss", "cross-site scripting", "CWE-79", "innerHTML", "escape", "textContent"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is fine",
    "looks good",
    "works as expected",
]
