"""Benchmark snippet 5: Off-by-one (MAJOR expected).

Classic off-by-one in a loop bound. The reviewer MUST:
- Report MAJOR severity
- Cite the loop line
- Explain the off-by-one (last element skipped)
- Suggest the fix (range(n) or range(1, n+1))

It MUST NOT:
- Say it's correct
- Skip the finding
- Report as NIT (off-by-one is a logic error)
"""

SNIPPET = '''def sum_first_n(arr, n):
    """Return sum of first n elements of arr."""
    total = 0
    for i in range(1, n):
        total += arr[i]
    return total


# Expected: sum_first_n([10, 20, 30, 40], 4) == 100
# Actual: sum_first_n([10, 20, 30, 40], 4) == 90 (skips arr[0])
'''

EXPECTED_SEVERITY = "MAJOR"
EXPECTED_LINE_REF = "4"  # the for loop line
EXPECTED_FINDING_KEYWORDS = ["off-by-one", "off by one", "skips", "range", "index"]
EXPECTED_VERDICT_CONTAINS = "Do not merge"

FORBIDDEN_PHRASES = [
    "this is correct",
    "looks good",
    "works as expected",
    "well done",
]
