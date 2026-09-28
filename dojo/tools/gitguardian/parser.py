import json

from dojo.models import Finding

# Mirrors severityFromString() in the GitGuardian connector's converter; anything unrecognised
# becomes Info.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# The connector's validityNarrative(). GitGuardian actively checks whether a discovered credential
# still authenticates, and that verdict is the most useful thing it reports, so it is spelled out
# rather than left as a bare enum value.
VALIDITY_NARRATIVE = {
    "valid": "**Validity:** valid — GitGuardian confirmed this credential is still live and actively exploitable.",
    "invalid": "**Validity:** invalid — the credential no longer authenticates.",
    "no_checker": "**Validity:** unverified — GitGuardian could not automatically check whether this credential is live; verify manually.",
    "not_checked": "**Validity:** unverified — GitGuardian could not automatically check whether this credential is live; verify manually.",
    "failed_to_check": "**Validity:** unverified — GitGuardian could not automatically check whether this credential is live; verify manually.",
}

# The connector's fixed mitigation text: every incident here is an exposed credential, and the
# remediation is always the same sequence.
MITIGATION = (
    "Revoke and rotate the exposed credential, then remove it from the codebase and purge it "
    "from version-control history. Review the incident in GitGuardian for the affected locations."
)


class GitGuardianParser:

    """
    Parses a GitGuardian secret-incidents export.

    Mirrors pkg/tools/gitguardian/connector/converter.go field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    One finding per GitGuardian incident, not per occurrence: an incident is a distinct exposed
    credential, and its occurrence count is reported in the description.

    Note the parser imports no secret value. GitGuardian's incidents endpoint does not return the
    matched secret, and nothing here reconstructs one.
    """

    def get_scan_types(self):
        # Byte-identical to ScanTypeName in the connector.
        return ["GitGuardian - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "GitGuardian - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a GitGuardian secret-incidents export (JSON). Matches the scan type used by the "
            "GitGuardian connector so file and API findings deduplicate. One finding per incident."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the GitGuardian Parser.

        Mirrors the connector's toFinding:
        - title: GitGuardian's own incident name, falling back to "<detector> detected".
        - severity: the incident severity, anything unrecognised Info.
        - description: what was exposed, the detector's family and category, GitGuardian's validity
          verdict, whether the secret is revoked, the occurrence count, and the incident link.
        - mitigation: the fixed revoke-rotate-purge sequence.
        - url: the GitGuardian incident link.
        - verified: true only when GitGuardian confirmed the credential is still live.
        - vuln_id_from_tool: the detector name, e.g. aws_iam.
        - unique_id_from_tool: "gitguardian-incident-<id>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "url",
            "verified",
            "vuln_id_from_tool",
            "unique_id_from_tool",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the GitGuardian Parser.

        Copied from the GitGuardian block in the Pro connector settings, which pairs the plain
        hash_code algorithm with the unique id alone - incident ids are stable, so nothing else is
        needed. Diverging would stop file findings merging with API-synced ones.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        incidents = self.extract_incidents(data)

        findings = {}
        for incident in incidents:
            if not isinstance(incident, dict):
                continue
            finding = self.build_finding(incident, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_incidents(self, data):
        """GitGuardian's incidents endpoint returns a bare array; envelopes are accepted too."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("incidents", "results", "data"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A GitGuardian export is a JSON array of secret incidents, or an object with an "
            f"'incidents' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, incident, test):
        detector = incident.get("detector") or {}

        finding = Finding(
            test=test,
            title=self.title(incident, detector),
            severity=SEVERITY_MAP.get(
                (incident.get("severity") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            description=self.describe(incident, detector),
            mitigation=MITIGATION,
            vuln_id_from_tool=detector.get("name") or None,
            unique_id_from_tool=f"gitguardian-incident-{incident.get('id')}",
        )

        if incident.get("gitguardian_url"):
            finding.url = incident["gitguardian_url"]
        # A confirmed-live secret is a verified finding. The converter sets this only for "valid";
        # an unchecked credential is not evidence of anything either way.
        if (incident.get("validity") or "").strip().lower() == "valid":
            finding.verified = True
        return finding

    def title(self, incident, detector):
        """GitGuardian's own incident name when it has one, otherwise "<detector> detected"."""
        if incident.get("incident_name"):
            return incident["incident_name"]
        return f"{detector.get('display_name') or 'Secret'} detected"

    def describe(self, incident, detector):
        kind = detector.get("display_name") or "secret"
        parts = [f"GitGuardian detected an exposed **{kind}**."]

        details = []
        if detector.get("family"):
            details.append(f"family {detector['family']}")
        if detector.get("category"):
            details.append(f"category {detector['category']}")
        if details:
            parts.append("**Detector:** " + ", ".join(details))

        narrative = VALIDITY_NARRATIVE.get((incident.get("validity") or "").strip().lower())
        if narrative:
            parts.append(narrative)

        if incident.get("secret_revoked"):
            parts.append("**Revoked:** the secret has been marked revoked in GitGuardian.")
        if (incident.get("occurrences_count") or 0) > 0:
            parts.append(f"**Occurrences:** {incident['occurrences_count']}")
        if incident.get("gitguardian_url"):
            parts.append("**Details:** " + incident["gitguardian_url"])
        return "\n\n".join(parts)
