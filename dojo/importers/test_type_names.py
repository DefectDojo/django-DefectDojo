"""
Test_Type names for reports whose parser names the test type itself (``get_tests``).

One scan type can carry reports from several tools (GitLab SAST: Semgrep, njsscan; SARIF; Generic),
so the importer names the Test_Type after the tool the report declares. The importer uses these
names to create a test and to check a reimport target, and ``AutoCreateContextManager`` uses the
same names to pick a reimport target by title, so both always agree on which tool a test belongs to.
"""


def dynamic_test_type_name(raw_type: str | None, scan_type: str) -> str:
    """
    Compute the Test_Type name for a dynamic-test-type report (e.g. Generic, SARIF).

    - No type, or type already equals the scan type -> use the scan type as-is.
    - Type already carries the scan-type suffix (e.g. "Prisma Cloud (Generic Findings
      Import)") -> use it verbatim. This keeps the composition idempotent and prevents
      doubled names like "X (scan_type) Scan (scan_type)".
    - Type plus a " Scan" suffix already equals the scan type (e.g. type "Horusec" with
      scan_type "Horusec Scan") -> use the scan type as-is. This preserves the behavior of
      dynamic parsers whose scan_type already ends in " Scan" (Horusec, AWS Security Hub,
      Rusty Hog, ...) so their Test_Type name is not doubled into "Horusec Scan (Horusec Scan)".
    - Otherwise -> the intentional "{type} Scan ({scan_type})" format (also used by SARIF,
      so a report labeled 'CodeScanner' becomes 'CodeScanner Scan (SARIF)').
    """
    if not raw_type or raw_type == scan_type:
        return scan_type
    if raw_type.endswith(f" ({scan_type})"):
        return raw_type
    if f"{raw_type} Scan" == scan_type:
        return scan_type
    return f"{raw_type} Scan ({scan_type})"


def legacy_dynamic_test_type_name(raw_type: str | None, scan_type: str) -> str:
    """
    Reproduce the name the pre-idempotency code produced. Used only for the reimport
    compatibility check so reimports into existing (pre-patch) tests whose test_type
    already has a doubled suffix keep working instead of raising a mismatch error.
    """
    if not raw_type or raw_type == scan_type:
        return scan_type
    name = f"{raw_type} Scan"
    if name != scan_type:
        name = f"{name} ({scan_type})"
    return name


def accepted_test_type_names(raw_type: str | None, scan_type: str) -> set[str]:
    """
    The Test_Type names a test may carry and still take a reimport of a report declaring ``raw_type``.

    The current name, the legacy (doubled) name, and the bare scan type. A test typed as the bare
    scan type was created from a report that named no tool, or outside the dynamic path, so it
    carries no tool identity to conflict with.
    """
    return {
        dynamic_test_type_name(raw_type, scan_type),
        legacy_dynamic_test_type_name(raw_type, scan_type),
        scan_type,
    }
