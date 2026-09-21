import json
from contextlib import suppress
from datetime import date as _date
from datetime import datetime

from dojo.models import Finding

SEVERITY_BY_NAME = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "none": "Info",
    "unknown": "Info",
}
DEFAULT_SEVERITY = "Info"

# Finite State's VEX statuses.
STATUS_NOT_AFFECTED = "NOT_AFFECTED"
STATUS_FIXED = "FIXED"
STATUS_UNDER_INVESTIGATION = "UNDER_INVESTIGATION"

# The NOT_AFFECTED justifications that mean the vulnerable code is not there to be reached, which
# makes the finding a false positive as well as out of scope.
FALSE_POSITIVE_JUSTIFICATIONS = {
    "COMPONENT_NOT_PRESENT",
    "VULNERABLE_CODE_NOT_PRESENT",
    "VULNERABLE_CODE_NOT_IN_EXECUTE_PATH",
}


class FinitestateParser:

    """
    Parses a Finite State findings export.

    Mirrors pkg/tools/finitestate/connector/finding_converter field for field so a file import and an
    API sync deduplicate against each other instead of producing two copies of everything.

    The VEX status is the part that carries real semantics. A NOT_AFFECTED finding is a product team's
    assertion that the vulnerability does not apply to this build, and it must not sit in DefectDojo
    as active - so it becomes out of scope, and a false positive too where the justification says the
    vulnerable code is not present or not reachable. See apply_status().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName.
        return ["Finite State - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Finite State - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Finite State findings export (JSON) for one firmware build, optionally with the "
            "asset and build context. Matches the scan type used by the Finite State connector so file "
            "and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Finite State Parser.

        Mirrors the connector's ConvertFinding:
        - title / description: Finite State's own, with the build context appended.
        - severity: the platform's severity, then its CVSS-derived one; see severity().
        - cwe: the first CWE that parses, accepting "CWE-79" or "79".
        - cvssv3 / cvssv3_score: the finding's score, then the first CVE's vector and base score.
        - epss_score / epss_percentile: the HIGHEST EPSS across the finding's CVEs.
        - component_name / component_version: the first affected SBOM component.
        - active / out_of_scope / false_p / is_mitigated / under_review: the VEX status.
        - unique_id_from_tool: the finding id; vuln_id_from_tool: Finite State's own.
        """
        return [
            "title",
            "description",
            "severity",
            "date",
            "cwe",
            "cvssv3",
            "cvssv3_score",
            "epss_score",
            "epss_percentile",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "out_of_scope",
            "false_p",
            "is_mitigated",
            "under_review",
            "static_finding",
            "dynamic_finding",
        ]

    # No get_dedupe_fields: this scan type has no curated hash-field list, so it deduplicates with
    # DefectDojo's default algorithm - which is exactly what the connector's own findings do today.
    # Choosing hash fields here would also change how those findings deduplicate, which is not this
    # parser's call to make. Noted in the PR as a follow-up on the connector side, because the
    # connector does write a stable unique_id_from_tool that the default algorithm cannot use.

    def get_findings(self, filename, test):
        data = json.load(filename)
        asset, version = self.context(data)
        return [
            self.build_finding(row, self.block(row, "asset") or asset,
                               self.block(row, "assetVersion") or version, test)
            for row in self.rows(data)
        ]

    def rows(self, data):
        """
        Return the findings in the export.

        Finite State answers GraphQL, so a saved export is {"data": {"allFindings": [...]}}. The
        unwrapped forms and a bare array are accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]

        if isinstance(data, dict):
            for holder in (self.block(data, "data"), data):
                for key in ("allFindings", "findings"):
                    if isinstance(holder.get(key), list):
                        return [row for row in holder[key] if isinstance(row, dict)]

        msg = (
            "A Finite State export is the findings response, a JSON object with a "
            f"'data.allFindings' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def context(self, data):
        """
        The asset and firmware build the whole file belongs to.

        One export is one firmware build, so the context is stated once for the file rather than
        repeated on every row - though a row carrying its own overrides it. A finding on firmware
        means little without knowing which build it is in, which is why the connector passes both
        into every conversion.
        """
        if not isinstance(data, dict):
            return None, None
        for holder in (data, self.block(data, "data")):
            asset = self.block(holder, "asset") or None
            version = self.block(holder, "assetVersion") or self.block(holder, "version") or None
            if asset or version:
                return asset, version
        return None, None

    def block(self, row, key):
        if not isinstance(row, dict):
            return {}
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    def blocks(self, row, key):
        value = row.get(key)
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def build_finding(self, row, asset, version, test):
        finding = Finding(
            test=test,
            title=str(row.get("title") or "") or None,
            description=self.describe(row, asset, version),
            severity=self.severity(row),
            cwe=self.cwe(row),
            unique_id_from_tool=str(row.get("id") or "") or None,
            vuln_id_from_tool=str(row.get("vulnIdFromTool") or "") or None,
            # Firmware and binary analysis inspect an artifact without running it.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = self.tags(row, version)

        # The first affected SBOM component is the component. Finite State can list several, but
        # DefectDojo has one - and the first is the one the finding is filed against.
        if affects := self.blocks(row, "affects"):
            finding.component_name = str(affects[0].get("name") or "") or None
            finding.component_version = str(affects[0].get("version") or "") or None

        if identifiers := self.vulnerability_ids(row):
            finding.unsaved_vulnerability_ids = identifiers
        if date := self.date(row):
            finding.date = date

        self.apply_scores(finding, row)
        self.apply_status(finding, row)
        return finding

    def severity(self, row):
        """
        Finite State's own severity, then its CVSS-derived one.

        Anything the platform does not recognise is Info - the connector logs a warning and does the
        same, because inventing a grade for an unknown word would be worse than under-reporting it.
        """
        for key in ("severity", "cvssSeverity"):
            label = str(row.get(key) or "").strip().lower()
            if label in SEVERITY_BY_NAME:
                return SEVERITY_BY_NAME[label]
        return DEFAULT_SEVERITY

    def cwe(self, row):
        """The first CWE that parses as a number, accepting "CWE-79" or "79"."""
        for cwe in self.blocks(row, "cwes"):
            digits = str(cwe.get("cweId") or "").strip().upper().removeprefix("CWE-")
            with suppress(ValueError):
                return int(digits)
        return 0

    def vulnerability_ids(self, row):
        """The finding's CVE identifiers, in the order Finite State lists them."""
        return [
            value
            for value in (str(cve.get("cveId") or "").strip() for cve in self.blocks(row, "cves"))
            if value
        ]

    def apply_scores(self, finding, row):
        """
        CVSS and EPSS, preferring the finding's own score and falling back to its first CVE's.

        EPSS is per-CVE, so the HIGHEST is taken: that is the finding's real exploitation likelihood,
        and its percentile travels with it rather than being mixed from another CVE.
        """
        finding.cvssv3_score = self.number(row.get("cvssScore"))

        for cve in self.blocks(row, "cves"):
            metric = self.block(self.block(cve, "cvssBaseMetricV3"), "cvssv3")
            if metric:
                if not finding.cvssv3:
                    finding.cvssv3 = str(metric.get("vectorString") or "") or None
                if not finding.cvssv3_score:
                    finding.cvssv3_score = self.number(metric.get("baseScore"))

            epss = self.block(cve, "epss")
            if epss:
                score = self.number(epss.get("epssScore"))
                if score > (finding.epss_score or 0):
                    finding.epss_score = score
                    finding.epss_percentile = self.number(epss.get("epssPercentile"))

    def apply_status(self, finding, row):
        """
        Translate the VEX status into DefectDojo's status flags.

        AFFECTED and anything unrecognised stay ACTIVE, which is the safe direction to be wrong in:
        a finding wrongly left active gets triaged, while one wrongly closed is never seen again.
        """
        current = row.get("currentStatus")
        if not isinstance(current, dict):
            # No assertion has been made, so the finding stands as reported.
            finding.active = True
            return

        status = str(current.get("status") or "").strip().upper()
        justification = str(current.get("justification") or "").strip().upper()

        if status == STATUS_NOT_AFFECTED:
            # A product team has asserted the vulnerability does not apply to this build.
            finding.active = False
            finding.out_of_scope = True
            if justification in FALSE_POSITIVE_JUSTIFICATIONS:
                # The vulnerable code is not there to be reached, so it is a false positive as well
                # as out of scope. The distinction matters for metrics.
                finding.false_p = True
        elif status == STATUS_FIXED:
            finding.active = False
            finding.is_mitigated = True
            if mitigated := self.timestamp(current.get("updatedAt")):
                finding.mitigated = mitigated
        elif status == STATUS_UNDER_INVESTIGATION:
            # Still active: nobody has ruled it out yet.
            finding.active = True
            finding.under_review = True
        else:
            finding.active = True

    def tags(self, row, version):
        """
        The firmware build, the finding category, the tools that produced it, and exploit intel.

        The build tag is what lets a reader tell which firmware a finding belongs to without opening
        it, which matters when several builds of one product are in the same product.
        """
        tags = []

        def add(value):
            trimmed = str(value or "").strip()
            if trimmed and trimmed not in tags:
                tags.append(trimmed)

        if version:
            add("firmware-build:" + self.first(version.get("name"), version.get("id")))

        add(row.get("category"))
        add(row.get("subcategory"))
        for source in row.get("sourceTypes") or []:
            add(source)
        for tool in self.blocks(self.block(row, "test"), "tools"):
            add(tool.get("name"))
        if row.get("regression"):
            add("regression")

        for cve in self.blocks(row, "cves"):
            exploits = self.block(cve, "exploitsInfo")
            if exploits.get("weaponized"):
                add("weaponized")
            if exploits.get("reportedInTheWild"):
                add("exploited-in-the-wild")
        return tags

    def describe(self, row, asset, version):
        """
        Finite State's own description, then the build context a reader needs.

        The connector does NOT trim this, so a description that ends in a field line keeps its
        trailing newline; reproduced rather than tidied so both paths render identically.
        """
        parts = []
        if description := str(row.get("description") or ""):
            parts.append(description + "\n\n")

        if asset:
            parts.append(f"**Asset:** {asset.get('name') or ''}\n")
        if version:
            parts.append(f"**Firmware build:** {self.first(version.get('name'), version.get('id'))}\n")
            if (risk := self.number(version.get("relativeRiskScore"))) > 0:
                parts.append(f"**Build relative risk score:** {self.plain(risk)}\n")

        for label, key in (("Category", "category"), ("Origin", "origin")):
            if value := str(row.get(key) or ""):
                parts.append(f"**{label}:** {value}\n")

        parts.append(self.vex_section(row.get("currentStatus")))

        if (risk := self.number(row.get("riskScore"))) > 0:
            parts.append(f"**Risk score:** {self.plain(risk)}\n")
        return "".join(parts)

    def vex_section(self, current):
        """The VEX assertion, which is the part of a firmware finding a reader most needs."""
        if not isinstance(current, dict) or not str(current.get("status") or ""):
            return ""

        lines = [f"**VEX status:** {current.get('status')}\n"]
        for label, key in (("VEX justification", "justification"), ("VEX comment", "comment")):
            if value := str(current.get(key) or ""):
                lines.append(f"**{label}:** {value}\n")
        return "".join(lines)

    def date(self, row):
        """
        The finding's date, then when it was created, cut back to the calendar date.

        The connector cuts at the "T" because it hands the API a string; this reads the same value as
        a date, and skips one that is not a date rather than failing the import.
        """
        value = self.first(row.get("date"), row.get("createdAt"))
        if not value:
            return None
        with suppress(ValueError):
            return _date.fromisoformat(value.split("T")[0])
        return None

    def timestamp(self, value):
        """A full timestamp, for the date a fix was asserted."""
        text = str(value or "").strip()
        if not text:
            return None
        with suppress(ValueError):
            return datetime.fromisoformat(text)
        return None

    def first(self, *values):
        for value in values:
            if trimmed := str(value or "").strip():
                return trimmed
        return ""

    def plain(self, value):
        """Shortest round-tripping form, as Go's FormatFloat(v, 'f', -1, 64) produces."""
        if value == int(value):
            return str(int(value))
        return repr(value)

    def number(self, value):
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0
