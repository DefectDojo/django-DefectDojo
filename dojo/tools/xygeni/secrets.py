"""
Parse Xygeni Secrets reports into DefectDojo Findings.

The Xygeni Secrets scanner already redacts the matched secret value in both
``secret`` and ``location.code`` before serialising the report, so this
parser surfaces those fields as-is.
"""

from pathlib import PurePosixPath

from dojo.models import Finding
from dojo.tools.xygeni._common import map_severity, parse_cwe

DEFAULT_CWE = 798  # CWE-798: Use of Hard-coded Credentials


def parse_secrets(data, test):
    """
    Convert a Xygeni Secrets JSON report into a list of Findings.

    The same secret value can be leaked on several lines of one file. Xygeni gives every such
    occurrence the same ``uniqueHash`` (it is location-independent by design), so the occurrences
    are aggregated into a single Finding whose description lists every line where the secret
    appears. This keeps the finding identity stable across scans: a synthetic per-line id would
    reopen findings whenever the lines shift.
    """
    groups = {}
    for secret in data.get("secrets") or []:
        key = secret.get("uniqueHash") or secret.get("issueId")
        groups.setdefault(key, []).append(secret)
    return [_build_finding(occurrences, test) for occurrences in groups.values()]


def _build_finding(occurrences, test):
    secret = occurrences[0]
    location = secret.get("location") or {}
    filepath = location.get("filepath") or ""
    filename = PurePosixPath(filepath).name or filepath or "unknown file"
    secret_type = secret.get("type") or secret.get("detector") or "secret"

    lines = []
    for occ in occurrences:
        begin_line = (occ.get("location") or {}).get("beginLine")
        if begin_line is not None and begin_line not in lines:
            lines.append(begin_line)
    lines.sort()

    description_parts = []
    if secret.get("description"):
        description_parts.append(str(secret["description"]))
    if location.get("code"):
        description_parts.append(f"```\n{location['code']}\n```")
    if len(lines) > 1:
        joined = ", ".join(str(line) for line in lines)
        description_parts.append(
            f"This secret is leaked {len(lines)} times in `{filename}`, on lines: {joined}.",
        )

    cwe = parse_cwe(tags=secret.get("tags")) or DEFAULT_CWE

    return Finding(
        test=test,
        title=f"{secret_type} secret detected in {filename}",
        description="\n\n".join(description_parts) if description_parts else "",
        severity=map_severity(secret.get("severity")),
        file_path=filepath or None,
        line=lines[0] if lines else location.get("beginLine"),
        cwe=cwe,
        mitigation=f"Rotate this {secret_type} secret immediately and remove it from version-control history.",
        static_finding=True,
        dynamic_finding=False,
        # ``uniqueHash`` is Xygeni's identity for the secret across scans: it hashes the secret
        # value + type + detector + file + key, with the line deliberately excluded. The same
        # secret leaked on several lines of one file shares it, so the occurrences are aggregated
        # into this single Finding (the lines are listed in the description above) instead of being
        # split with a synthetic per-line id that would churn across scans. ``detector`` is the
        # secret type, used as the non-unique grouping id.
        unique_id_from_tool=secret.get("uniqueHash"),
        vuln_id_from_tool=secret.get("detector"),
    )
