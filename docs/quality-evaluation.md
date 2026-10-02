**Maintainer:** Frangel Raúl Crespo Barrera
**Last verified:** 2026-10-02
**Scope:** MCP review workflow, benchmarks, security post-processing, and repository-content handling.

| Field | Current record |
|---|---|
| Status | CI is publishing-only; a separate validation workflow is not present. |
| Evidence | `src/`, `benchmarks/`, `tests/test_benchmarks.py`, `tests/test_security.py`, `pyproject.toml`, `.github/workflows/publish.yml`. |
| Standard | OWASP capabilities are declared capabilities, not validated detection rates; ASVS version is not pinned in this policy. |
| Verification | `pytest -q`; inspect benchmark corpus version and run the existing security tests. |
| Owner | Repository owner maintains corpus and evaluation methodology. |
| Limitations | No precision/recall or coverage claim is made without a versioned corpus and reproducible run. |

Treat repository input as untrusted text. Do not execute input, return secrets in messages or logs, or allow unbounded diffs and requests. Add a separate validation workflow only after its commands and failure policy are agreed.
