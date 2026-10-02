import json
import re
from contextlib import suppress
from datetime import datetime

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# Assessed resource types the connector imports: Defender Vulnerability Management emits the Azure*
# names, the older per-solution scanners used the unprefixed ones.
VULNERABILITY_RESOURCE_TYPES = frozenset({
    "ServerVulnerabilityTvm",
    "AzureContainerRegistryVulnerability",
    "AzureServerVulnerabilityAssessment",
    "ContainerRegistryVulnerability",
    "ServerVulnerabilityAssessment",
})
CONTAINER_RESOURCE_TYPES = frozenset({
    "AzureContainerRegistryVulnerability",
    "ContainerRegistryVulnerability",
})
# Posture and configuration sub-assessments, explicitly excluded: they carry no CVEs.
POSTURE_RESOURCE_TYPES = frozenset({"SqlServerVulnerability", "GeneralVulnerability"})

# The status code for a resource with an open finding.
STATUS_UNHEALTHY = "Unhealthy"

# Anchored, as the connector's own pattern is: a reference title is a CVE id or it is prose.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


class DefenderForCloudParser:

    """
    Parses a Microsoft Defender for Cloud sub-assessments export.

    Mirrors pkg/tools/defendercloud/connector/finding_converter field for field so a file import and an
    API sync deduplicate against each other instead of producing two copies of everything.

    Defender for Cloud returns every kind of sub-assessment through one endpoint - server
    vulnerabilities, container-registry image vulnerabilities, SQL baselines, posture checks - and the
    same field means different things in each. The vulnerable package lives under softwareDetails for a
    container finding and in a flat softwareName for a server one, which is why component_name reads
    both; see component_name().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["Microsoft Defender for Cloud - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Microsoft Defender for Cloud - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Microsoft Defender for Cloud sub-assessments export (JSON), the ARM "
            "subAssessments response. Matches the scan type used by the Defender for Cloud connector "
            "so file and API findings deduplicate. Only open vulnerability sub-assessments are "
            "imported - SQL baselines and posture checks are not."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Microsoft Defender for Cloud Parser.

        Mirrors the connector's Convert:
        - title: the display name, with the package appended when the name is a bare CVE.
        - severity: Defender's own label; anything unrecognised is Info.
        - severity_justification: the label and the CVSS base score it came with.
        - description: the assessed resource, the image and digest for a container finding, the
          package, the fixed version, then Defender's prose.
        - mitigation: the version to update to, then Defender's own remediation text.
        - impact: Defender's impact statement, imported as-is.
        - component_name / component_version: the vulnerable package, read from either shape.
        - unique_id_from_tool: the sub-assessment's ARM id, which is the whole deduplication hash.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "date",
            "description",
            "mitigation",
            "impact",
            "references",
            "component_name",
            "component_version",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Microsoft Defender for Cloud Parser.

        Copied from the Defender for Cloud block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with a hash of the unique id ALONE. The ARM sub-assessment id
        already encodes the subscription, the resource and the finding, so it is the whole identity.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for row in self.rows(data):
            if not self.is_open(row) or not self.is_vulnerability(row):
                # Healthy sub-assessments are left out so a reimport closes them, and SQL/posture
                # sub-assessments are not vulnerabilities at all.
                continue
            findings.append(self.build_finding(row, test))
        return findings

    def rows(self, data):
        """
        Return the sub-assessments in the export.

        The ARM envelope nests them under "value"; a bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("value", "subAssessments"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]
            if "properties" in data:
                return [data]

        msg = (
            "A Defender for Cloud export is the subAssessments response, a JSON object with a 'value' "
            f"list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def properties(self, row):
        value = row.get("properties")
        return value if isinstance(value, dict) else {}

    def block(self, source, key):
        value = source.get(key)
        return value if isinstance(value, dict) else {}

    def additional(self, row):
        return self.block(self.properties(row), "additionalData")

    def is_open(self, row):
        """Only an Unhealthy sub-assessment is an open finding."""
        return str(self.block(self.properties(row), "status").get("code") or "") == STATUS_UNHEALTHY

    def is_vulnerability(self, row):
        """
        Whether this sub-assessment is a vulnerability rather than a posture check.

        The resource type decides when it is one the connector knows. For an unfamiliar type the
        presence of a CVE decides instead - a new Defender scanner should not be dropped silently, but
        a configuration baseline should not arrive as a vulnerability either.
        """
        resource_type = str(self.additional(row).get("assessedResourceType") or "")
        if resource_type in VULNERABILITY_RESOURCE_TYPES:
            return True
        if resource_type in POSTURE_RESOURCE_TYPES:
            return False
        return bool(self.cve_ids(row))

    def build_finding(self, row, test):
        properties = self.properties(row)
        raw_severity = str(self.block(properties, "status").get("severity") or "")
        score, is_v3, found = self.best_cvss(row)

        finding = Finding(
            test=test,
            title=self.title(row),
            severity=SEVERITY_BY_LABEL.get(raw_severity.lower(), DEFAULT_SEVERITY),
            severity_justification=self.severity_justification(raw_severity, score, is_v3, found),
            description=self.describe(row),
            mitigation=self.mitigation(row),
            impact=str(properties.get("impact") or ""),
            references=self.references(row),
            component_name=self.component_name(row) or None,
            component_version=self.component_version(row) or None,
            unique_id_from_tool=str(row.get("id") or "") or None,
            vuln_id_from_tool=self.vuln_id(row),
            # Defender reads an inventory of installed software and images; nothing is exercised.
            static_finding=False,
            dynamic_finding=True,
        )

        if identifiers := self.cve_ids(row):
            finding.unsaved_vulnerability_ids = identifiers
        # Only a v3 base goes in the v3 field; Defender also reports v2 scores.
        if found and is_v3 and score > 0:
            finding.cvssv3_score = score
        if date := self.date(properties):
            finding.date = date
        return finding

    def vuln_id(self, row):
        """The CVE, then the display name, then Defender's own finding id."""
        properties = self.properties(row)
        vulnerability = self.block(self.additional(row), "vulnerabilityDetails")
        for candidate in (vulnerability.get("cveId"), properties.get("displayName"), properties.get("id")):
            value = str(candidate or "")
            if value:
                return value
        return None

    def title(self, row):
        """
        The display name, with the package appended when the name is a bare CVE.

        "CVE-2000-0001" alone says nothing about what is affected, and one CVE usually appears against
        several packages on the same host.
        """
        name = str(self.properties(row).get("displayName") or "")
        if not name:
            return self.vuln_id(row) or ""
        package = self.component_name(row)
        if package and name.upper().startswith("CVE-"):
            return f"{name} in {package}"
        return name

    def component_name(self, row):
        """The container shape puts the package under softwareDetails; the server shape flattens it."""
        additional = self.additional(row)
        if name := str(self.block(additional, "softwareDetails").get("packageName") or ""):
            return name
        return str(additional.get("softwareName") or "")

    def component_version(self, row):
        additional = self.additional(row)
        if version := str(self.block(additional, "softwareDetails").get("version") or ""):
            return version
        return str(additional.get("softwareVersion") or "")

    def fixed_version(self, row):
        additional = self.additional(row)
        if version := str(self.block(additional, "softwareDetails").get("fixedVersion") or ""):
            return version
        return str(additional.get("recommendedVersion") or "")

    def describe(self, row):
        properties = self.properties(row)
        additional = self.additional(row)
        parts = []

        if resource := self.resource_label(row):
            parts.append(f"**Assessed resource:** {resource}\n")

        if str(additional.get("assessedResourceType") or "") in CONTAINER_RESOURCE_TYPES:
            artifact = self.block(additional, "artifactDetails")
            repository = str(artifact.get("repositoryName") or "")
            if repository:
                parts.append(f"**Image:** {artifact.get('registryHost') or ''}/{repository}\n")
            if digest := str(artifact.get("digest") or ""):
                parts.append(f"**Digest:** {digest}\n")

        if package := self.component_name(row):
            parts.append(f"**Package:** {package} {self.component_version(row)}\n")
        if fixed := self.fixed_version(row):
            parts.append(f"**Fixed version:** {fixed}\n")
        if description := str(properties.get("description") or ""):
            parts.append(f"\n{description}\n")
        return "".join(parts).rstrip("\n")

    def mitigation(self, row):
        """
        The version to update to, then Defender's own remediation text.

        Both are kept because they answer different questions: the version says what to do, and
        Defender's text says how - and neither is always present.
        """
        parts = []
        package, fixed = self.component_name(row), self.fixed_version(row)
        if package and fixed:
            parts.append(f"Update {package} to {fixed} or later.")
        if remediation := str(self.properties(row).get("remediation") or "").strip():
            parts.append(remediation)
        return "\n\n".join(parts)

    def severity_justification(self, raw_severity, score, is_v3, found):
        justification = f"Defender for Cloud assigned severity **{raw_severity}**."
        if found:
            version = "v3" if is_v3 else "v2"
            justification += f" CVSS {version} base score {score:.1f}."
        return justification

    def references(self, row):
        links = []
        vulnerability = self.block(self.additional(row), "vulnerabilityDetails")
        for reference in vulnerability.get("references") or []:
            if not isinstance(reference, dict):
                continue
            if link := str(reference.get("link") or ""):
                links.append(link)
        return "\n".join(links)

    def cve_ids(self, row):
        """
        The CVE, the display name, the reference titles and the TVM CVE list.

        Every candidate is matched against an ANCHORED pattern, because a reference title is either a
        CVE id or it is prose - a substring match would pull an id out of a sentence.
        """
        properties = self.properties(row)
        additional = self.additional(row)
        vulnerability = self.block(additional, "vulnerabilityDetails")

        candidates = [vulnerability.get("cveId"), properties.get("displayName")]
        candidates.extend(
            reference.get("title")
            for reference in vulnerability.get("references") or []
            if isinstance(reference, dict)
        )
        candidates.extend(self.tvm_cve_titles(additional.get("cve")))

        identifiers, seen = [], set()
        for candidate in candidates:
            value = str(candidate or "").strip()
            if not CVE_PATTERN.match(value):
                continue
            if value.upper() not in seen:
                seen.add(value.upper())
                identifiers.append(value)
        return identifiers

    def tvm_cve_titles(self, source):
        """
        Defender's TVM CVE field arrives as a list, a single object, or a bare string.

        The connector's decoder accepts all three, so a file that carries any of them reads the same.
        """
        if isinstance(source, str):
            return [source]
        rows = source if isinstance(source, list) else [source]
        titles = []
        for row in rows:
            if isinstance(row, str):
                titles.append(row)
            elif isinstance(row, dict):
                titles.append(str(row.get("title") or ""))
        return titles

    def best_cvss(self, row):
        """
        The highest CVSS base score reported, and whether it is v3.

        Defender reports a flat v3.0 score on some shapes and a version-keyed map on others, and the
        highest wins - which is the connector's choice, so a file import grades the same way.
        """
        additional = self.additional(row)
        best, is_v3, found = 0.0, False, False

        flat = additional.get("cvssV30Score")
        if isinstance(flat, int | float) and not isinstance(flat, bool) and flat > 0:
            best, is_v3, found = float(flat), True, True

        scores = self.block(self.block(additional, "vulnerabilityDetails"), "cvss")
        for version, entry in scores.items():
            if not isinstance(entry, dict):
                continue
            base = entry.get("base")
            if not isinstance(base, int | float) or isinstance(base, bool) or base <= best:
                continue
            best, is_v3, found = float(base), str(version).startswith("3"), True
        return best, is_v3, found

    def resource_label(self, row):
        """
        The resource name, else the last segment of an ARM or native resource id.

        An ARM id is a path, and its last segment is the resource - printing the whole path would bury
        the one part a reader needs.
        """
        details = self.block(self.properties(row), "resourceDetails")
        if name := str(details.get("ResourceName") or ""):
            return name
        for key in ("NativeResourceId", "id"):
            candidate = str(details.get(key) or "")
            if not candidate:
                continue
            index = candidate.rfind("/")
            if 0 <= index < len(candidate) - 1:
                return candidate[index + 1:]
            return candidate
        return ""

    def date(self, properties):
        """Defender timestamps are RFC 3339; the connector keeps the first ten characters."""
        generated = str(properties.get("timeGenerated") or "")
        if len(generated) < 10:
            return None
        with suppress(ValueError):
            return datetime.strptime(generated[:10], "%Y-%m-%d").date()
        return None
