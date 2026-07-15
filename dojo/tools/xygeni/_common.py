"""Shared helpers for the Xygeni multi-scan-type parser."""

import re

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

_CWE_TAG_RE = re.compile(r"^CWE[:\-]?(\d+)$", re.IGNORECASE)


def map_severity(value):
    """Map a Xygeni lowercase severity to a DefectDojo severity. Unknown values become Info."""
    if value is None:
        return "Info"
    return SEVERITY_MAP.get(str(value).lower(), "Info")


def parse_cwe(cwes=None, cwe=None, tags=None):
    """
    Resolve the primary CWE integer from any of the Xygeni representations.

    Preference order:
    1. The numeric ``cwe`` field on the finding.
    2. The first ``"CWE-N"`` entry in ``cwes``.
    3. The first ``"CWE:N"`` / ``"cwe:N"`` entry in ``tags``.
    """
    primary, _ = parse_cwes(cwes=cwes, cwe=cwe, tags=tags)
    return primary


def parse_cwes(cwes=None, cwe=None, tags=None):
    """
    Resolve CWEs from any of the Xygeni representations.

    Returns a ``(primary, all_cwes)`` tuple where ``primary`` is the single CWE
    kept on ``Finding.cwe`` (following the :func:`parse_cwe` preference order)
    and ``all_cwes`` is the deduplicated, order-preserving list of every CWE
    integer found across the ``cwe``/``cwes``/``tags`` inputs. ``primary`` is
    ``None`` when no CWE is present.
    """
    all_cwes = []
    seen = set()

    def _add(value):
        if value is not None and value not in seen:
            seen.add(value)
            all_cwes.append(value)

    if isinstance(cwe, int):
        _add(cwe)
    for entry in cwes or []:
        match = _CWE_TAG_RE.match(str(entry))
        if match:
            _add(int(match.group(1)))
    for entry in tags or []:
        match = _CWE_TAG_RE.match(str(entry))
        if match:
            _add(int(match.group(1)))

    primary = all_cwes[0] if all_cwes else None
    return primary, all_cwes


def extract_scan_type(data):
    """Read ``metadata.scanType`` from a Xygeni report. Raises ``ValueError`` if absent."""
    if not isinstance(data, dict):
        msg = "Xygeni report root must be a JSON object"
        raise TypeError(msg)
    metadata = data.get("metadata") or {}
    scan_type = metadata.get("scanType")
    if not scan_type:
        msg = "Xygeni report is missing required 'metadata.scanType' field"
        raise ValueError(msg)
    return str(scan_type).lower()
