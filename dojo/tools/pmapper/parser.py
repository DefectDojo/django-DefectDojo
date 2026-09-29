import json

from dojo.models import Finding


class PMapperParser:

    """
    Parser for PMapper (Principal Mapper), NCC Group's AWS IAM privilege escalation analyser.

    PMapper builds a graph of the IAM principals in an account and works out who can reach whom.
    ``pmapper analysis --output-type json`` writes a report holding the account it analysed and a
    list of findings, each with the severity PMapper assigned, the impact, a description naming
    the principals involved, and a recommendation.
    """

    # principalmapper/analysis/find_risks.py assigns these severity strings.
    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }
    DEFAULT_SEVERITY = "Medium"

    def get_scan_types(self):
        return ["PMapper Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import PMapper (Principal Mapper) reports in JSON format, generated with "
            "'pmapper --account <account> analysis --output-type json'."
        )

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for report in data if isinstance(data, list) else [data]:
            if not isinstance(report, dict):
                continue
            account = report.get("account")
            source = report.get("source")
            analysed_at = report.get("date_and_time")
            findings.extend(
                self._to_finding(entry, account, source, analysed_at, test)
                for entry in report.get("findings") or []
                if isinstance(entry, dict)
            )
        return findings

    def _to_finding(self, entry, account, source, analysed_at, test):
        title = entry.get("title") or "PMapper finding"

        description = []
        if entry.get("description"):
            description.append(entry["description"])
        if entry.get("impact"):
            description.append(f"**Impact:** {entry['impact']}")
        if account:
            description.append(f"**AWS account:** {account}")
        if source:
            description.append(f"**Analysis source:** {source}")
        if analysed_at:
            description.append(f"**Analysed at:** {analysed_at}")

        return Finding(
            title=f"{title} ({account})" if account else title,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get((entry.get("severity") or "").lower(), self.DEFAULT_SEVERITY),
            mitigation=entry.get("recommendation") or None,
            impact=entry.get("impact") or None,
            component_name=account or None,
            vuln_id_from_tool=title,
            static_finding=True,
            dynamic_finding=False,
        )
