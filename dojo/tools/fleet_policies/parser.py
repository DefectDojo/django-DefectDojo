import json
import re
from contextlib import suppress
from ipaddress import ip_address

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Fleet reports a policy's outcome per host; only a failing one is a finding.
POLICY_RESPONSE_FAIL = "fail"

CRITICAL_POLICY_SEVERITY = "High"
POLICY_SEVERITY = "Medium"


# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class FleetPoliciesParser:

    """
    Parses a Fleet host export, importing the compliance policies that are failing.

    Mirrors the policy half of pkg/tools/fleet/connector/converter field for field so a file import
    and an API sync deduplicate against each other instead of producing two copies of everything. The
    software CVEs in the same export are a separate scan type - see the Fleet Vulnerabilities parser -
    because Fleet's own API models them as different things and the two carry different deduplication
    keys.

    A Fleet host response nests the policy results inside the host, so one file produces a finding per
    host per failing policy.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypePolicies.
        return ["Fleet:Policies - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Fleet:Policies - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Fleet host export (JSON) and report the compliance policies failing on each "
            "host. Matches the scan type used by the Fleet connector so file and API findings "
            "deduplicate. Software CVEs in the same export are imported by the Fleet "
            "Vulnerabilities parser."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Fleet Policies Parser.

        Mirrors the connector's policyFinding:
        - title: the policy name.
        - severity: High for a policy Fleet marks critical, Medium otherwise.
        - description: the policy description, that it is failing, the host, and the policy's query.
        - mitigation: the policy's own resolution text.
        - unique_id_from_tool: "<host id>:policy:<policy id>".
        - vuln_id_from_tool: "fleet-policy-<policy id>", the policy itself.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Fleet Policies Parser.

        Copied from the Fleet policies block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Note it hashes vuln_id_from_tool -
        the policy - rather than a component, because a policy is not about a package.
        """
        return ["title", "severity", "vuln_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for host in self.hosts(data):
            for policy in self.rows(host.get("policies")):
                finding = self.build_finding(host, policy, test)
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
            if any(key in data for key in ("software", "policies", "hostname", "display_name")):
                return [data]

        msg = (
            "A Fleet export is a host response, a JSON object with a 'hosts' list or a single 'host'; "
            f"got {type(data).__name__}."
        )
        raise TypeError(msg)

    def rows(self, value):
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []

    def build_finding(self, host, policy, test):
        if not self.failing(policy):
            # A passing policy is not a finding, and Fleet reports every policy's outcome.
            return None
        title = str(policy.get("name") or "").strip()
        if not title:
            # Without a name there is nothing to report; the connector drops the row.
            return None

        critical = policy.get("critical") is True
        policy_id = self.flex_int(policy.get("id"))

        finding = Finding(
            test=test,
            title=title,
            severity=CRITICAL_POLICY_SEVERITY if critical else POLICY_SEVERITY,
            description=self.describe(host, policy),
            mitigation=str(policy.get("resolution") or "").strip(),
            unique_id_from_tool=f"{self.flex_int(host.get('id'))}:policy:{policy_id}",
            vuln_id_from_tool=f"fleet-policy-{policy_id}",
            # A policy is an osquery query run against the host's own state.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = self.tags(host, policy, critical)

        self.attach_host(finding, host)
        return finding

    def failing(self, policy):
        """Fleet writes the outcome as "fail" or "pass", and leaves it empty when it has no result."""
        return str(policy.get("response") or "").strip().lower() == POLICY_RESPONSE_FAIL

    def describe(self, host, policy):
        parts = []
        if description := str(policy.get("description") or "").strip():
            parts.append(description)
        parts.append("This Fleet policy is **failing** on this host.")
        parts.extend(self.host_lines(host))
        if query := str(policy.get("query") or "").strip():
            parts.append("**Policy query**\n\n```sql\n" + query + "\n```")
        return "\n\n".join(parts)

    def tags(self, host, policy, critical):
        """
        The connector sorts and deduplicates its tags, so these come out alphabetical.

        Worth mirroring rather than tidying: a tag set that differs only in order still reads as a
        change on every reimport.
        """
        tags = ["policy", "compliance", "endpoint"]
        if critical:
            tags.append("critical-policy")
        tags.extend([
            str(policy.get("platform") or "").strip(),
            str(host.get("platform") or "").strip(),
        ])
        return sorted({tag for tag in tags if tag})

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
        if settings.V3_FEATURE_LOCATIONS:
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

    def flex_int(self, value):
        """Fleet sends ids as either a number or a numeric string."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            trimmed = value.strip().strip('"')
            with suppress(ValueError):
                return int(trimmed)
        return 0
