import json
import re
from contextlib import suppress
from ipaddress import ip_address

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_BY_BUCKET = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"

# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class Action1Parser:

    """
    Parses an Action1 vulnerability export.

    Mirrors pkg/tools/action1/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Action1 needs two calls to describe a finding: the vulnerability list, and the endpoints affected
    by each CVE. The affected endpoint is what makes a finding - a vulnerability with none produces
    nothing at all - so an export needs both; see extract(). A third call, the managed-endpoint list,
    supplies each machine's operating system, which the connector treats as best-effort enrichment.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Action1 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Action1 Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Action1 vulnerability export (JSON). Matches the scan type used by the Action1 "
            "connector so file and API findings deduplicate. Include the endpoints affected by each "
            "CVE - a vulnerability with no affected endpoint is not a finding."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Action1 Parser.

        Mirrors the connector's Convert:
        - title: the vulnerability name, then the CVE id, then a constant.
        - severity: the base severity, falling back to Action1's own score bucket; see severity().
        - description: the CVE, the endpoint, its OS and the remediation status.
        - mitigation: the updates Action1 has available for the affected software.
        - component_name / component_version: the vulnerable software on that endpoint.
        - unique_id_from_tool: "action1-<CVE>-<endpoint id>" - one CVE per affected machine.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Action1 Parser.

        Copied from the Action1 block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The component version is among them,
        so a machine that has been partly patched does not merge with one that has not.
        """
        return ["title", "severity", "component_name", "component_version"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        vulnerabilities, affected, operating_systems = self.extract(data)

        findings = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            for endpoint in self.endpoints_for(vulnerability, affected):
                identifier = str(endpoint.get("endpoint_id") or "").strip()
                if not identifier:
                    # The connector skips an affected-endpoint row with no id: it cannot be
                    # identified, and the id is half of the finding's own identity.
                    continue
                findings.append(self.build_finding(vulnerability, endpoint, operating_systems, test))
        return findings

    def extract(self, data):
        """
        Return the vulnerabilities, the endpoints affected by each CVE, and each machine's OS.

        Action1 pages every list under "items". The affected endpoints come from a second call, one
        per CVE, so an export carries them either as a top-level map keyed by CVE id or nested on each
        vulnerability. The managed-endpoint list, keyed by endpoint id, supplies the OS.
        """
        affected, operating_systems = {}, {}
        vulnerabilities = None

        if isinstance(data, list):
            vulnerabilities = data
        elif isinstance(data, dict):
            for key in ("items", "vulnerabilities"):
                if isinstance(data.get(key), list):
                    vulnerabilities = data[key]
                    break
            affected = self.index_affected(data)
            operating_systems = self.index_operating_systems(data)

        if vulnerabilities is None:
            msg = (
                "An Action1 export is the vulnerability-list response, a JSON object with an 'items' "
                f"list; got {type(data).__name__}."
            )
            raise TypeError(msg)
        return vulnerabilities, affected, operating_systems

    def index_affected(self, data):
        """The affected endpoints as a map keyed by CVE id, accepting a couple of spellings."""
        for key in ("endpoints", "affected_endpoints"):
            source = data.get(key)
            if isinstance(source, dict):
                return {
                    str(cve): [row for row in rows if isinstance(row, dict)]
                    for cve, rows in source.items()
                    if isinstance(rows, list)
                }
        return {}

    def index_operating_systems(self, data):
        """
        Managed endpoints, indexed id -> OS.

        Action1 spells the field "OS", capitalised, in its managed-endpoint response.
        """
        indexed = {}
        for key in ("managed_endpoints", "endpoints_managed"):
            source = data.get(key)
            rows = source.get("items") if isinstance(source, dict) else source
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                identifier = str(row.get("id") or "").strip()
                name = str(row.get("OS") or row.get("os") or "").strip()
                if identifier and name:
                    indexed[identifier] = name
            break
        return indexed

    def endpoints_for(self, vulnerability, affected):
        """The affected endpoints nested on the vulnerability, else those indexed by its CVE id."""
        for key in ("endpoints", "affected_endpoints"):
            nested = vulnerability.get(key)
            if isinstance(nested, list):
                return [row for row in nested if isinstance(row, dict)]
            if isinstance(nested, dict) and isinstance(nested.get("items"), list):
                return [row for row in nested["items"] if isinstance(row, dict)]
        return affected.get(str(vulnerability.get("cve_id") or "").strip(), [])

    def build_finding(self, vulnerability, endpoint, operating_systems, test):
        cve = str(vulnerability.get("cve_id") or "").strip()
        identifier = str(endpoint.get("endpoint_id") or "").strip()
        software = self.primary_software(vulnerability, endpoint)

        finding = Finding(
            test=test,
            title=self.title(vulnerability, cve),
            severity=self.severity(vulnerability),
            description=self.describe(vulnerability, endpoint, operating_systems, cve),
            mitigation=self.mitigation(software),
            unique_id_from_tool=f"action1-{cve}-{identifier}",
            vuln_id_from_tool=cve or None,
            # Action1 reads an installed-software inventory from the agent; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            # The connector marks every finding active: Action1 only reports what is still present.
            active=True,
        )
        # Set unconditionally, as the connector does - an unscored vulnerability lands as 0.0.
        finding.cvssv3_score = self.flex_float(vulnerability.get("cvss_score"))

        if cve:
            finding.unsaved_vulnerability_ids = [cve]
        if software is not None:
            finding.component_name = str(software.get("product_name") or "").strip() or None
            finding.component_version = self.installed_version(software) or None

        self.attach_endpoint(finding, endpoint)
        return finding

    def title(self, vulnerability, cve):
        if name := str(vulnerability.get("name") or "").strip():
            return name
        if cve:
            return cve
        return "Action1 vulnerability"

    def severity(self, vulnerability):
        """
        Grade the vulnerability.

        Action1 reports a base severity and, separately, a "score" that is also a word rather than a
        number - Critical/High/Medium/Low. The base severity wins, the score is the fallback, and
        anything unrecognised is Info.
        """
        bucket = str(vulnerability.get("base_severity") or "").strip()
        if not bucket:
            bucket = str(vulnerability.get("score") or "").strip()
        return SEVERITY_BY_BUCKET.get(bucket.lower(), DEFAULT_SEVERITY)

    def describe(self, vulnerability, endpoint, operating_systems, cve):
        """
        The connector joins these with a SINGLE newline, not a blank line.

        Mirrored rather than tidied: the description is part of nothing that hashes here, but a
        gratuitous difference between the two import paths is still a difference.
        """
        lines = []

        def add(label, value):
            text = str(value or "").strip()
            if text:
                lines.append(f"**{label}:** {text}")

        add("CVE", cve)
        add("Endpoint", self.endpoint_name(endpoint))
        add("OS", operating_systems.get(str(endpoint.get("endpoint_id") or "").strip()))
        add("Remediation status", vulnerability.get("remediation_status"))
        return "\n".join(lines)

    def endpoint_name(self, endpoint):
        """The endpoint's name, falling back to its id."""
        if name := str(endpoint.get("endpoint_name") or "").strip():
            return name
        return str(endpoint.get("endpoint_id") or "").strip()

    def mitigation(self, software):
        """"Apply: <name> <version>, ..." from the updates Action1 has ready for that software."""
        if software is None:
            return ""
        updates = software.get("available_updates")
        if not isinstance(updates, list):
            return ""

        fixes = []
        for update in updates:
            if not isinstance(update, dict):
                continue
            label = str(update.get("name") or "").strip()
            if version := str(update.get("version") or "").strip():
                label = f"{label} {version}".strip()
            if label:
                fixes.append(label)
        return "Apply: " + ", ".join(fixes) if fixes else ""

    def primary_software(self, vulnerability, endpoint):
        """
        The first software entry on the affected endpoint, else the first on the vulnerability.

        Action1 lists the software per endpoint because the installed version differs by machine,
        which is exactly why the endpoint's copy is preferred.
        """
        for source in (endpoint, vulnerability):
            rows = source.get("software")
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        return row
        return None

    def installed_version(self, software):
        versions = software.get("versions")
        if isinstance(versions, list):
            for version in versions:
                if isinstance(version, dict):
                    return str(version.get("version") or "").strip()
        return ""

    def attach_endpoint(self, finding, endpoint):
        """
        Record the affected machine.

        The connector groups findings by endpoint into products rather than writing an endpoint, so
        this is additional context rather than a mirrored field - and it is dropped unless the name is
        something DefectDojo will accept as a host, since an Action1 endpoint name is free text.
        """
        name = self.endpoint_name(endpoint)
        if not name or not self.usable_host(name):
            return
        if locations_enabled():
            finding.unsaved_locations.append(LocationData.url(host=name))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(host=name))

    def usable_host(self, value):
        """
        Whether DefectDojo will accept this as an endpoint host.

        A host is letters, digits, dot, hyphen, underscore or plus, or an IP address. Anything else -
        a machine name with a space in it - makes Endpoint.clean() raise, and that fails the whole
        import rather than the one finding. The name is still in the description.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    def flex_float(self, value):
        """Action1 sends its CVSS score as either a number or a numeric string."""
        if value is None or isinstance(value, bool):
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0
