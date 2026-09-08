import json

from dojo.models import Finding

# Mirrors severityFromLevel() in the Google Cloud SCC connector's converter. SCC also emits
# SEVERITY_UNSPECIFIED, which falls through to Info like anything else unrecognised.
SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}
DEFAULT_SEVERITY = "Info"

# SCC does not always set a category, and the connector names the finding rather than leaving the
# title empty.
DEFAULT_CATEGORY = "Security Command Center finding"


class GoogleSCCParser:

    """
    Parses a Google Cloud Security Command Center findings export.

    Mirrors pkg/tools/googlescc/connector/converter.go field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    SCC's ListFindings response pairs each finding with the resource it was found on, and the two are
    siblings rather than nested - the resource carries the display name and type that make the finding
    readable, so both halves have to be read.
    """

    def get_scan_types(self):
        # Byte-identical to ScanTypeName in the connector.
        return ["Google Cloud SCC - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Google Cloud SCC - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Google Cloud Security Command Center findings export (JSON, the ListFindings "
            "response). Matches the scan type used by the Google Cloud SCC connector so file and API "
            "findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Google Cloud SCC Parser.

        Mirrors the connector's toFinding:
        - title: "<category> - <resource display name>", or the category alone.
        - severity: SCC's severity level; anything unrecognised Info.
        - description: SCC's description, the finding class, the affected resource, and the link.
        - url: SCC's externalUri, when it has one.
        - vuln_id_from_tool: the SCC category, which is its rule identifier.
        - unique_id_from_tool: the finding's full resource name, which is globally unique.
        - cvssv3_score: the CVE's CVSS v3 base score, for vulnerability-class findings.
        """
        return [
            "title",
            "severity",
            "description",
            "url",
            "cvssv3_score",
            "vuln_id_from_tool",
            "unique_id_from_tool",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Google Cloud SCC Parser.

        Copied from the Google Cloud SCC block in the Pro connector settings: the finding's full
        resource name is globally unique, so the plain hash_code algorithm hashes it alone.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        results = self.extract_results(data)

        findings = {}
        for result in results:
            if not isinstance(result, dict):
                continue
            finding_data, resource = self.split(result)
            if finding_data is None:
                continue
            finding = self.build_finding(finding_data, resource, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_results(self, data):
        """SCC's ListFindings response pages the results under "listFindingsResults"."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("listFindingsResults", "results", "findings"):
                if isinstance(data.get(key), list):
                    return data[key]
        msg = (
            "A Google Cloud SCC export is the ListFindings response, a JSON object with a "
            f"'listFindingsResults' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def split(self, result):
        """
        Separate the finding from the resource it was found on.

        They are siblings in the response, not nested. A result that carries the finding's own fields
        directly is accepted too, for an export somebody has already flattened.
        """
        finding = result.get("finding")
        if isinstance(finding, dict):
            resource = result.get("resource")
            return finding, resource if isinstance(resource, dict) else {}
        # Flattened: the entry is the finding itself.
        if result.get("name") or result.get("category"):
            resource = result.get("resource")
            return result, resource if isinstance(resource, dict) else {}
        return None, {}

    def build_finding(self, finding_data, resource, test):
        category = finding_data.get("category") or ""
        external_uri = finding_data.get("externalUri") or ""

        finding = Finding(
            test=test,
            title=self.title(category, resource),
            severity=SEVERITY_MAP.get(
                (finding_data.get("severity") or "").strip().upper(), DEFAULT_SEVERITY,
            ),
            description=self.describe(finding_data, resource, external_uri),
            # The SCC category is its rule identifier, e.g. PUBLIC_BUCKET_ACL.
            vuln_id_from_tool=category or None,
            # The finding's full resource name is globally unique across the organisation.
            unique_id_from_tool=finding_data.get("name"),
        )

        if external_uri:
            finding.url = external_uri

        cve = self.cve(finding_data)
        if cve:
            finding.unsaved_vulnerability_ids = [cve["id"]]
            cvss = cve.get("cvssv3")
            if isinstance(cvss, dict) and (cvss.get("baseScore") or 0) > 0:
                finding.cvssv3_score = cvss["baseScore"]
        return finding

    def title(self, category, resource):
        """The category, qualified by the resource it was found on when SCC names one."""
        label = category or DEFAULT_CATEGORY
        display_name = resource.get("displayName") or ""
        if display_name:
            return f"{label} - {display_name}"
        return label

    def describe(self, finding_data, resource, external_uri):
        parts = []
        if finding_data.get("description"):
            parts.append(finding_data["description"])
        if finding_data.get("findingClass"):
            parts.append(f"**Finding class:** {finding_data['findingClass']}")

        # The resource type and name, space-joined, in the connector's order.
        details = [
            value for value in (resource.get("type"), resource.get("name")) if value
        ]
        if details:
            parts.append("**Resource:** " + " ".join(details))

        if external_uri:
            parts.append(f"**Reference:** {external_uri}")
        return "\n\n".join(parts)

    def cve(self, finding_data):
        """
        The CVE on a vulnerability-class finding, if there is one.

        SCC reports many classes - misconfiguration, threat, observation - and only some carry a CVE,
        so this is nested behind two optional objects.
        """
        vulnerability = finding_data.get("vulnerability")
        if not isinstance(vulnerability, dict):
            return None
        cve = vulnerability.get("cve")
        if isinstance(cve, dict) and cve.get("id"):
            return cve
        return None
