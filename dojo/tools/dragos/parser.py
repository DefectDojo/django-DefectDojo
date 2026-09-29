import json
import re
from contextlib import suppress

from dojo.models import Finding

# The advisory identifiers the connector's shared extractor recognises in free text.
VULNERABILITY_ID_PATTERN = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+|RHSA-\d{4}:\d+",
)


class DragosParser:

    """
    Parses a Dragos Platform vulnerability-detection export.

    Mirrors pkg/tools/dragos/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    Dragos covers OT assets, and a detection carries the asset it was found on rather than pointing
    at one - so the whole export is a single list and no join is needed. The OT context that makes a
    finding actionable (the Purdue level, the zone, the vendor and model of the device, and whether
    the flaw is known to be exploited in the wild) is what the description and the severity
    justification carry; see describe() and justification().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Dragos Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Dragos Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Dragos Platform vulnerability-detection export (JSON), each detection carrying "
            "the OT asset it was found on. Matches the scan type used by the Dragos connector so file "
            "and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Dragos Parser.

        Mirrors the connector's Convert:
        - title: the vulnerability title, then the Dragos advisory id, then the internal id.
        - severity: the CVSS base score, falling back to Dragos's own 0-5 scale; see severity().
        - severity_justification: Dragos's OT exploitability context; see justification().
        - description: the summary, the advisory, and the asset's vendor, model, firmware, zone,
          Purdue level and addresses.
        - mitigation: Dragos's mitigations, one per line.
        - component_name / component_version: the OT asset and its firmware version.
        - unsaved_vulnerability_ids: advisory ids found in the reference, enumeration and title.
        - unique_id_from_tool: "dragos-<vulnerability id>-<asset id>".
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "description",
            "mitigation",
            "cvssv3_score",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Dragos Parser.

        Copied from the Dragos block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The asset is the component, so the
        same flaw on two devices stays two findings - which is the point in an OT estate, where the
        two devices may sit at different Purdue levels.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        return [self.build_finding(row, test) for row in self.detections(data)]

    def detections(self, data):
        """
        Return the detections in the export.

        Dragos pages its detections endpoint as {"content": [...]}, so that is the shape a saved
        export has. A bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("content", "detections", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A Dragos export is the detections response, a JSON object with a 'content' list; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def block(self, row, key):
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    def build_finding(self, row, test):
        vuln = self.block(row, "vulnerability")
        host = self.block(row, "host")
        asset = self.asset_name(host)

        finding = Finding(
            test=test,
            title=self.title(vuln),
            severity=self.severity(vuln),
            description=self.describe(vuln, host, asset),
            mitigation=self.mitigation(vuln),
            component_name=asset or None,
            component_version=str(self.firmware(host) or "") or None,
            unique_id_from_tool=f"dragos-{vuln.get('id') or ''}-{host.get('id') or ''}",
            vuln_id_from_tool=self.vuln_id(vuln),
            # Dragos matches an asset inventory against advisories; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.cvssv3_score = self.base_score(vuln)
        finding.unsaved_tags = self.tags(vuln, host)

        if identifiers := self.vulnerability_ids(vuln):
            finding.unsaved_vulnerability_ids = identifiers
        if justification := self.justification(vuln):
            finding.severity_justification = justification
        return finding

    def vuln_id(self, vuln):
        """The Dragos advisory id, then the enumeration, the reference and the internal id."""
        for key in ("report_id", "enumeration", "reference", "id"):
            if value := str(vuln.get(key) or "").strip():
                return value
        return None

    def title(self, vuln):
        for key in ("title", "report_id"):
            if str(vuln.get(key) or "").strip():
                return str(vuln.get(key))
        return f"Dragos vulnerability {vuln.get('id') or ''}"

    def severity(self, vuln):
        """
        The CVSS base score decides; Dragos's own 0-5 scale is the fallback.

        CVSS is the most portable signal Dragos exposes. Its own scale runs the other way from a
        score - 5 is the most severe - so reading one as the other would inverte the whole ladder.
        """
        if (score := self.base_score(vuln)) > 0:
            if score >= 9.0:
                return "Critical"
            if score >= 7.0:
                return "High"
            if score >= 4.0:
                return "Medium"
            return "Low"

        level = self.flex_float(vuln.get("severity"))
        if level >= 5:
            return "Critical"
        if level >= 4:
            return "High"
        if level >= 3:
            return "Medium"
        if level >= 2:
            return "Low"
        return "Info"

    def base_score(self, vuln):
        return self.flex_float(self.block(vuln, "score").get("base"))

    def asset_name(self, host):
        """
        The OT asset: its name, then its first hostname, then its first address, then its id.

        An OT device often has no name and no hostname at all, which is why the address is a
        fallback - a finding with no component would lose which device has to be patched. The
        hostname is only used when it is not blank; the address is used whenever the list has an
        entry at all, which is the connector's own asymmetry.
        """
        if value := str(host.get("name") or "").strip():
            return value

        hostnames = self.items(host.get("hostname"))
        if hostnames and hostnames[0].strip():
            return hostnames[0]

        addresses = self.items(host.get("ip"))
        if addresses:
            return addresses[0]
        return str(host.get("id") or "")

    def firmware(self, host):
        return self.block(self.block(host, "hardware"), "firmware").get("version")

    def vendor(self, host):
        """The asset's own vendor, falling back to the vendor of its hardware."""
        if value := str(host.get("vendor") or "").strip():
            return value
        return str(self.block(host, "hardware").get("vendor") or "")

    def purdue_level(self, host):
        """
        The Purdue (PERA) level, which is ABSENT rather than zero when Dragos does not know it.

        Level 0 is the physical process layer - a real level, and the most sensitive one - so an
        absent level and level 0 must not render alike.
        """
        value = host.get("pera_level")
        if value is None:
            return ""
        return str(self.flex_int(value))

    def describe(self, vuln, host, asset):
        lines = []

        def write(label, value):
            if str(value or "").strip():
                lines.append(f"**{label}:** {value}")

        hardware = self.block(host, "hardware")
        write("Summary", vuln.get("summary"))
        write("Description", vuln.get("description"))
        write("Dragos advisory", vuln.get("report_id"))
        write("Asset", asset)
        write("Vendor", self.vendor(host))
        write("Model", hardware.get("model"))
        write("Firmware", self.firmware(host))
        write("Zone", self.block(host, "zone").get("name"))
        write("Purdue level", self.purdue_level(host))
        write("IP", ", ".join(self.items(host.get("ip"))))
        return "\n".join(lines).strip()

    def mitigation(self, vuln):
        """Dragos's mitigations, one per line, exactly as it lists them."""
        return "\n".join(self.items(vuln.get("mitigations"))) or None

    def justification(self, vuln):
        """
        Dragos's OT exploitability context and its own risk score.

        In an OT estate this is the difference between a flaw that has to be handled in the next
        maintenance window and one that can wait for the next outage, so it is recorded as the
        severity justification rather than being used to move the severity.
        """
        intel = self.block(vuln, "intel")
        reasons = []
        if intel.get("active_exploit"):
            reasons.append("actively exploited")
        if intel.get("poc_exists"):
            reasons.append("public proof of concept exists")
        if intel.get("remotely_exploitable"):
            reasons.append("remotely exploitable")
        if (score := self.flex_float(vuln.get("dragos_score"))) > 0:
            reasons.append(f"Dragos risk score {self.number(score)}")

        if not reasons:
            return ""
        return "Dragos OT context: " + "; ".join(reasons) + "."

    def tags(self, vuln, host):
        """The asset's vendor, model, zone and type, plus OT and exploited flags, for filtering."""
        hardware = self.block(host, "hardware")
        tags = [
            value
            for value in (
                self.vendor(host),
                str(hardware.get("model") or ""),
                str(self.block(host, "zone").get("name") or ""),
                str(host.get("type") or ""),
            )
            if value.strip()
        ]
        if host.get("is_ot"):
            tags.append("ot-asset")
        if self.block(vuln, "intel").get("active_exploit"):
            tags.append("active-exploit")
        return tags

    def vulnerability_ids(self, vuln):
        """
        Advisory ids read out of the reference, the enumeration and the title.

        The connector's shared extractor joins those three with "|", matches them all, then SORTS and
        drops case-insensitive duplicates - so the order here is alphabetical rather than the order
        they appear in, unlike the connectors that use the order-preserving call.
        """
        text = "|".join(str(vuln.get(key) or "") for key in ("reference", "enumeration", "title"))
        matches = sorted(VULNERABILITY_ID_PATTERN.findall(text))

        identifiers = []
        for match in matches:
            # Adjacent-only dedupe after the sort, which is what slices.CompactFunc does.
            if not identifiers or identifiers[-1].lower() != match.lower():
                identifiers.append(match)
        return identifiers

    def items(self, value):
        """
        The list as strings, keeping blanks.

        The connector joins these lists without filtering, so dropping a blank entry here would
        render a different description than an API sync of the same data.
        """
        if not isinstance(value, list):
            return []
        return [str(item) if item is not None else "" for item in value]

    def number(self, value):
        """Shortest round-tripping form, as Go's FormatFloat(v, 'f', -1, 64) produces."""
        if value == int(value):
            return str(int(value))
        return repr(value)

    def flex_float(self, value):
        """Dragos's numbers may arrive as JSON numbers or quoted strings."""
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0

    def flex_int(self, value):
        return int(self.flex_float(value))
