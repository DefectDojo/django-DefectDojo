import json
import re
from contextlib import suppress
from datetime import datetime
from ipaddress import ip_address

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# CVSS floors. Note the default when a CVE carries NO score at all is Medium, not Info: Fleet enriches
# from the NVD, and a CVE it has not scored yet is an unknown rather than a non-issue.
CVSS_CRITICAL_FLOOR = 9.0
CVSS_HIGH_FLOOR = 7.0
CVSS_MEDIUM_FLOOR = 4.0
UNSCORED_SEVERITY = "Medium"


# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class FleetVulnerabilitiesParser:

    """
    Parses a Fleet host export, importing the CVEs found in installed software.

    Mirrors the vulnerability half of pkg/tools/fleet/connector/converter field for field so a file
    import and an API sync deduplicate against each other instead of producing two copies of
    everything. The compliance-policy half of the same export is a separate scan type - see the Fleet
    Policies parser - because Fleet's own API models them as different things and the two carry
    different deduplication keys.

    A Fleet host response nests software inside the host and the CVEs inside each software row, so one
    file produces a finding per host per software per CVE.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeVulnerabilities.
        return ["Fleet:Vulnerabilities - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Fleet:Vulnerabilities - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Fleet host export (JSON) and report the CVEs in each host's installed "
            "software. Matches the scan type used by the Fleet connector so file and API findings "
            "deduplicate. Failing compliance policies in the same export are imported by the Fleet "
            "Policies parser."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Fleet Vulnerabilities Parser.

        Mirrors the connector's vulnerabilityFinding:
        - title: "<CVE> - <software> <version> on <host>".
        - severity: graded from the CVSS score; an unscored CVE is Medium.
        - description: the CVE summary, the software, the host, the CPE and the risk lines.
        - mitigation: the version that resolves the CVE, when Fleet reported one.
        - component_name / component_version: the installed software.
        - cvssv3_score / publish_date: from Fleet's NVD enrichment.
        - unique_id_from_tool: "<host id>:<software>:<version>:<CVE>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "component_version",
            "cvssv3_score",
            "publish_date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Fleet Vulnerabilities Parser.

        Copied from the Fleet vulnerabilities block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for host in self.hosts(data):
            for software in self.rows(host.get("software")):
                for cve in self.rows(software.get("vulnerabilities")):
                    finding = self.build_finding(host, software, cve, test)
                    if finding is not None:
                        findings.append(finding)
        return findings

    def hosts(self, data):
        """
        Return the hosts in the export.

        Fleet's host list nests them under "hosts" and its single-host response under "host", so both
        are accepted; a bare array of hosts works too.
        """
        if isinstance(data, list):
            return [host for host in data if isinstance(host, dict)]
        if isinstance(data, dict):
            if isinstance(data.get("hosts"), list):
                return [host for host in data["hosts"] if isinstance(host, dict)]
            if isinstance(data.get("host"), dict):
                return [data["host"]]
            # A host response, used directly.
            if any(key in data for key in ("software", "policies", "hostname", "display_name")):
                return [data]

        msg = (
            "A Fleet export is a host response, a JSON object with a 'hosts' list or a single 'host'; "
            f"got {type(data).__name__}."
        )
        raise TypeError(msg)

    def rows(self, value):
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []

    def build_finding(self, host, software, cve, test):
        identifier = str(cve.get("cve") or "").strip()
        if not identifier:
            # The connector drops a vulnerability row with no CVE id: there is nothing to report.
            return None

        name = str(software.get("name") or "")
        version = str(software.get("version") or "")
        score = self.score(cve)

        finding = Finding(
            test=test,
            title=self.title(host, name, version, identifier),
            severity=self.severity(score),
            description=self.describe(host, software, cve, name, version, score),
            mitigation=self.mitigation(name, cve),
            component_name=name.strip() or None,
            component_version=version or None,
            unique_id_from_tool=self.unique_id(host, name, version, identifier),
            vuln_id_from_tool=identifier,
            # Fleet reads an installed-software inventory from the host; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_vulnerability_ids = [identifier]
        finding.unsaved_tags = self.tags(host, cve)

        if score is not None:
            finding.cvssv3_score = score
        if published := self.published(cve):
            finding.publish_date = published

        self.attach_host(finding, host)
        return finding

    def title(self, host, name, version, identifier):
        title = identifier
        if name:
            title += f" - {name}"
            if version:
                title += f" {version}"
        if hostname := self.host_name(host):
            title += f" on {hostname}"
        return title

    def unique_id(self, host, name, version, identifier):
        """"<host id>:<software>:<version>:<CVE>" - the same CVE on two hosts is two findings."""
        return ":".join([str(self.flex_int(host.get("id"))), name, version, identifier])

    def severity(self, score):
        """
        Grade the CVSS score.

        A CVE Fleet has not scored is Medium rather than Info - it is an unknown, not a non-issue -
        but an explicit zero is Info.
        """
        if score is None:
            return UNSCORED_SEVERITY
        if score >= CVSS_CRITICAL_FLOOR:
            return "Critical"
        if score >= CVSS_HIGH_FLOOR:
            return "High"
        if score >= CVSS_MEDIUM_FLOOR:
            return "Medium"
        if score > 0:
            return "Low"
        return "Info"

    def describe(self, host, software, cve, name, version, score):
        parts = []
        if summary := self.text(cve.get("cve_description")):
            parts.append(summary)

        if name:
            line = f"**Software:** {name}"
            if version:
                line += f" {version}"
            extra = [value for value in (software.get("source"), software.get("vendor")) if value]
            if extra:
                line += " (" + ", ".join(str(value) for value in extra) + ")"
            parts.append(line)

        parts.extend(self.host_lines(host))

        if cpe := str(software.get("generated_cpe") or "").strip():
            parts.append(f"**CPE:** {cpe}")

        parts.extend(self.risk_lines(cve, score))
        return "\n\n".join(parts)

    def risk_lines(self, cve, score):
        lines = []
        if score is not None:
            lines.append(f"**CVSS:** {self.render_number(score)}")
        epss = self.flex_float(cve.get("epss_probability"))
        if epss is not None:
            lines.append(
                f"**EPSS:** {self.render_number(epss)} "
                "(probability of exploitation in the next 30 days)",
            )
        if cve.get("cisa_known_exploit") is True:
            lines.append(
                "**CISA KEV:** this CVE is on CISA's Known Exploited Vulnerabilities list and should "
                "be prioritized regardless of its CVSS score.",
            )
        return lines

    def mitigation(self, name, cve):
        if fix := self.text(cve.get("resolved_in_version")):
            return f"Upgrade {name or 'the affected software'} to {fix} or later, which resolves this CVE."
        return (
            "Update the affected software to a release that resolves this CVE, following the vendor's "
            "security advisory. Fleet did not report a fixed version for this vulnerability."
        )

    def tags(self, host, cve):
        """
        The connector sorts and deduplicates its tags, so these come out alphabetical.

        Worth mirroring rather than tidying: a tag set that differs only in order still reads as a
        change on every reimport.
        """
        tags = ["vulnerability", "endpoint", str(host.get("platform") or "").strip()]
        if cve.get("cisa_known_exploit") is True:
            tags.append("cisa-known-exploited")
        return sorted({tag for tag in tags if tag})

    def published(self, cve):
        """Fleet sends the NVD publication timestamp; only the date is kept."""
        published = self.text(cve.get("cve_published"))
        if not published:
            return None
        with suppress(ValueError):
            return datetime.strptime(published.split("T")[0], "%Y-%m-%d").date()
        return None

    def host_name(self, host):
        """Fleet's display name, then the computer name, then the hostname."""
        for key in ("display_name", "computer_name", "hostname"):
            if value := str(host.get(key) or "").strip():
                return value
        return ""

    def host_lines(self, host):
        lines = []
        if name := self.host_name(host):
            line = f"**Host:** {name}"
            if address := str(host.get("primary_ip") or ""):
                line += f" ({address})"
            lines.append(line)
        if operating_system := self.operating_system(host):
            lines.append(f"**OS:** {operating_system}")
        return lines

    def operating_system(self, host):
        platform = str(host.get("platform") or "").strip()
        version = str(host.get("os_version") or "").strip()
        return f"{platform} {version}".strip()

    def attach_host(self, finding, host):
        """The endpoint is the host itself - Fleet inventories machines, not URLs."""
        name = self.host_name(host) or str(host.get("primary_ip") or "").strip()
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
        a path, a space, a container image tag - makes Endpoint.clean() raise, and that fails the
        whole import rather than the one finding, so it is dropped here instead. The value is still
        reported in the description, so nothing is lost.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    def score(self, cve):
        return self.flex_float(cve.get("cvss_score"))

    def flex_float(self, value):
        """
        Fleet sends these numbers as either a number or a numeric string.

        An absent or null value means "not scored"; an empty string is a zero, which is how the
        connector's own decoder reads it.
        """
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            trimmed = value.strip().strip('"')
            if trimmed in {"", "null"}:
                return 0.0
            with suppress(ValueError):
                return float(trimmed)
        return None

    def flex_int(self, value):
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            trimmed = value.strip().strip('"')
            with suppress(ValueError):
                return int(trimmed)
        return 0

    def render_number(self, value):
        """Render a float the way the connector does - 7.5 stays 7.5, but 9.0 prints as 9."""
        return str(int(value)) if value == int(value) else repr(value)

    def text(self, value):
        return str(value).strip() if value is not None else ""
