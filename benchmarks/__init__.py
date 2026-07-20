"""Benchmark snippets package."""

from .snippet_01_sql_injection import SNIPPET as SNIPPET_1, EXPECTED_SEVERITY as SEV_1
from .snippet_02_mutable_default import SNIPPET as SNIPPET_2, EXPECTED_SEVERITY as SEV_2
from .snippet_03_clean_code import SNIPPET as SNIPPET_3, EXPECTED_SEVERITY as SEV_3
from .snippet_04_swallowed_exception import SNIPPET as SNIPPET_4, EXPECTED_SEVERITY as SEV_4
from .snippet_05_off_by_one import SNIPPET as SNIPPET_5, EXPECTED_SEVERITY as SEV_5
from .snippet_06_hardcoded_credentials import SNIPPET as SNIPPET_6, EXPECTED_SEVERITY as SEV_6
from .snippet_07_path_traversal import SNIPPET as SNIPPET_7, EXPECTED_SEVERITY as SEV_7
from .snippet_08_xss import SNIPPET as SNIPPET_8, EXPECTED_SEVERITY as SEV_8
from .snippet_09_deserialization import SNIPPET as SNIPPET_9, EXPECTED_SEVERITY as SEV_9
from .snippet_10_idor import SNIPPET as SNIPPET_10, EXPECTED_SEVERITY as SEV_10

BENCHMARKS = [
    ("sql_injection", SNIPPET_1, SEV_1),
    ("mutable_default", SNIPPET_2, SEV_2),
    ("clean_code", SNIPPET_3, SEV_3),
    ("swallowed_exception", SNIPPET_4, SEV_4),
    ("off_by_one", SNIPPET_5, SEV_5),
    ("hardcoded_credentials", SNIPPET_6, SEV_6),
    ("path_traversal", SNIPPET_7, SEV_7),
    ("xss", SNIPPET_8, SEV_8),
    ("deserialization", SNIPPET_9, SEV_9),
    ("idor", SNIPPET_10, SEV_10),
]

__all__ = ["BENCHMARKS"]
