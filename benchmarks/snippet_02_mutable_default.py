"""Benchmark snippet 2: Mutable default argument (MAJOR expected).

Classic Python gotcha. The reviewer MUST:
- Report MAJOR (or CRITICAL) severity
- Cite line 1 (function signature with default=[])
- Explain the mutable default bug
- Suggest default=None pattern

It MUST NOT:
- Skip the finding
- Say it's fine
- Report it as NIT (it's worse than that)
"""

SNIPPET = '''def append_to_list(value, target=[]):
    """Append value to target list, return the list."""
    target.append(value)
    return target


# Usage
print(append_to_list(1))
print(append_to_list(2))
# Output: [1]
#         [1, 2]  <- bug! Should be [2]
'''

EXPECTED_SEVERITY = "MAJOR"
EXPECTED_LINE_REF = "1"
EXPECTED_FINDING_KEYWORDS = ["mutable default", "default argument", "none", "shared state"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is fine",
    "looks good",
    "works as expected",
]
