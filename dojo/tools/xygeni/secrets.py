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
    """Convert a Xygeni Secrets JSON report into a list of Findings."""
    return [_build_finding(secret, test) for secret in data.get("secrets") or []]


def _build_finding(secret, test):
    location = secret.get("location") or {}
    filepath = location.get("filepath") or ""
    filename = PurePosixPath(filepath).name or filepath or "unknown file"
    secret_type = secret.get("type") or secret.get("detector") or "secret"

    description_parts = []
    if secret.get("description"):
        description_parts.append(str(secret["description"]))
    if location.get("code"):
        description_parts.append(f"```\n{location['code']}\n```")

    cwe = parse_cwe(tags=secret.get("tags")) or DEFAULT_CWE

    return Finding(
        test=test,
        title=f"{secret_type} secret detected in {filename}",
        description="\n\n".join(description_parts) if description_parts else "",
        severity=map_severity(secret.get("severity")),
        file_path=filepath or None,
        line=location.get("beginLine"),
        cwe=cwe,
        mitigation=f"Rotate this {secret_type} secret immediately and remove it from version-control history.",
        static_finding=True,
        dynamic_finding=False,
        # The same secret value can appear several times in one file. Xygeni assigns every
        # occurrence the same ``uniqueHash`` (it hashes the secret value, not the location)
        # but a distinct ``issueId`` (which encodes filepath + line). Dedup is keyed on
        # ``unique_id_from_tool``, so use the per-occurrence ``issueId`` to keep each
        # occurrence as its own Finding; ``uniqueHash`` groups them as the vuln id.
        unique_id_from_tool=secret.get("issueId") or secret.get("uniqueHash"),
        vuln_id_from_tool=secret.get("uniqueHash"),
    )
