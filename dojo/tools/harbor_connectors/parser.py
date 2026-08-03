import json
import re

from dojo.models import Finding

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Harbor omits the description on plenty of advisories, and the connector says so explicitly rather
# than leaving the field empty.
NO_DESCRIPTION = "No description found"

CWE_PATTERN = re.compile(r"^CWE-(\d+)", re.IGNORECASE)


class HarborConnectorsParser:

    """
    Parses a Harbor vulnerability report.

    Mirrors pkg/tools/harbor/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    A Harbor report describes ONE scanned artifact, and the artifact's identity is not in the report
    body - the connector supplies it from the repository and artifact it fetched. See artifact_ref().

    Note DefectDojo also ships a `harbor_vulnerability` parser under the scan type
    "Harbor Vulnerability Scan"; this is a separate parser for the connector's own scan type.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType(), and distinct from the existing
        # "Harbor Vulnerability Scan".
        return ["Harbor - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Harbor - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Harbor vulnerability report (JSON). Matches the scan type used by the Harbor "
            "connector so file and API findings deduplicate. Include the repository and digest in "
            "the export so findings carry the same identity the connector gives them."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Harbor Parser.

        Mirrors the connector's VulnerabilityToFinding:
        - title: "<vulnerability id> - <package> (<version>)".
        - severity: Harbor's severity word; anything unrecognised Info.
        - description: the advisory text, or "No description found", plus the image and digest.
        - component_name / component_version: the affected package and its installed version.
        - service: the repository the artifact came from.
        - mitigation: set only when Harbor reports a fix version.
        - references: the advisory links, one per line.
        - cwe: the first CWE id, parsed from "CWE-<n>".
        - unique_id_from_tool: "<repository>@<digest or tag>:<id>:<package>:<version>".
        """
        return [
            "title",
            "severity",
            "description",
            "component_name",
            "component_version",
            "service",
            "mitigation",
            "references",
            "cwe",
            "unique_id_from_tool",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Harbor Parser.

        Copied from the Harbor block in the Pro connector settings: the composed tool id already
        carries the repository, artifact, vulnerability and package, so the plain hash_code algorithm
        hashes it alone.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        report, ref = self.extract(data)

        findings = {}
        for vulnerability in report:
            if not isinstance(vulnerability, dict):
                continue
            finding = self.build_finding(vulnerability, ref, test)
            findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract(self, data):
        """
        Return the vulnerability list and the artifact reference.

        Harbor's scan endpoint keys the report by the scanner's MIME type, so a saved export is often
        an object whose single value is the report. The bare report object and a bare vulnerability
        array are both accepted too.
        """
        if isinstance(data, list):
            return data, self.artifact_ref({})

        if not isinstance(data, dict):
            msg = (
                "A Harbor report is a JSON object with a 'vulnerabilities' list, or a bare array of "
                f"vulnerabilities; got {type(data).__name__}."
            )
            raise TypeError(msg)

        if isinstance(data.get("vulnerabilities"), list):
            return data["vulnerabilities"], self.artifact_ref(data)

        # A MIME-keyed envelope: find the first value that looks like a report.
        for value in data.values():
            if isinstance(value, dict) and isinstance(value.get("vulnerabilities"), list):
                # The artifact context may sit on either level, so the outer object wins and the
                # inner one fills the gaps.
                ref = self.artifact_ref(data)
                inner = self.artifact_ref(value)
                for key, fallback in inner.items():
                    ref[key] = ref[key] or fallback
                return value["vulnerabilities"], ref

        msg = (
            "A Harbor report is a JSON object with a 'vulnerabilities' list, or the scanner "
            f"MIME-type envelope containing one; got an object with keys {sorted(data)[:5]}."
        )
        raise TypeError(msg)

    def artifact_ref(self, source):
        """
        Read the artifact context the connector supplies from what it fetched.

        None of this is in Harbor's report body, so an export has to carry it for the tool id and the
        image context to match the connector's. Both the API's own field names and the flatter names
        a hand-built export tends to use are accepted.
        """
        tags = source.get("tags")
        tag = ""
        if isinstance(tags, list) and tags:
            first = tags[0]
            tag = first.get("name") or "" if isinstance(first, dict) else str(first)
        return {
            "repository": source.get("repository") or source.get("repository_name") or "",
            "tag": source.get("tag") or tag,
            "digest": source.get("digest") or "",
        }

    def build_finding(self, vulnerability, ref, test):
        package = vulnerability.get("package") or ""
        version = vulnerability.get("version") or ""
        vuln_id = vulnerability.get("id") or ""

        finding = Finding(
            test=test,
            title=f"{vuln_id} - {package} ({version})",
            severity=SEVERITY_MAP.get(
                (vulnerability.get("severity") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            description=self.describe(vulnerability, ref),
            component_name=package or None,
            component_version=version or None,
            service=ref["repository"] or None,
            unique_id_from_tool=self.unique_id(vulnerability, ref, package, version, vuln_id),
            # A registry scan reads a built image, never a running service.
            static_finding=True,
            dynamic_finding=False,
        )

        if vulnerability.get("fix_version"):
            finding.mitigation = (
                f"Upgrade {package} to version {vulnerability['fix_version']}"
            )
        links = vulnerability.get("links")
        if isinstance(links, list):
            joined = "\n".join(str(link) for link in links if link)
            if joined:
                finding.references = joined
        cwe = self.first_cwe(vulnerability.get("cwe_ids"))
        if cwe:
            finding.cwe = cwe
        # Harbor also reports advisory ids that are not CVEs, and the connector only records the
        # vulnerability id when it actually is one.
        if vuln_id.upper().startswith("CVE"):
            finding.unsaved_vulnerability_ids = [vuln_id]
        return finding

    def describe(self, vulnerability, ref):
        description = vulnerability.get("description") or NO_DESCRIPTION
        return description + self.image_context(ref)

    def image_context(self, ref):
        """The image and digest the finding came from, appended to the advisory text."""
        image = ref["repository"]
        if ref["tag"]:
            image += f":{ref['tag']}"
        context = f"\n\n**Image:** {image}"
        if ref["digest"]:
            context += f"\n**Digest:** {ref['digest']}"
        return context

    def unique_id(self, vulnerability, ref, package, version, vuln_id):
        """
        Compose the connector's identity: repository, artifact, vulnerability, package, version.

        The digest is preferred over the tag because a tag can be moved to a different image, which
        would silently merge findings from two artifacts.
        """
        reference = ref["digest"] or ref["tag"]
        return f"{ref['repository']}@{reference}:{vuln_id}:{package}:{version}"

    def first_cwe(self, cwe_ids):
        if not isinstance(cwe_ids, list) or not cwe_ids:
            return 0
        match = CWE_PATTERN.match(str(cwe_ids[0]).strip())
        return int(match.group(1)) if match else 0
