import json

from dojo.models import Finding


class TwoMsParser:

    """
    Parser for 2ms (too many secrets) JSON reports.

    2ms groups its results by the identity it assigns each secret, so a single secret found
    in several places appears once per location under the same key.
    """

    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    def get_scan_types(self):
        return ["2ms Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import 2ms (too many secrets) reports in JSON format, generated with '2ms --report-path <dir> --report-format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for results in (data.get("results") or {}).values():
            findings.extend(self._to_finding(result, test) for result in results)
        return findings

    def _to_finding(self, result, test):
        rule_name = result.get("ruleName")
        source = result.get("source")
        start_line = result.get("startLine")

        description = []
        if result.get("ruleDescription"):
            description.append(result["ruleDescription"])
        if source:
            description.append(f"**Source:** {source}")
        if result.get("ruleCategory"):
            description.append(f"**Category:** {result['ruleCategory']}")
        if result.get("validationStatus"):
            description.append(f"**Validation status:** {result['validationStatus']}")
        if result.get("lineContent"):
            description.append(f"**Line content:** `{result['lineContent']}`")
        # 2ms keys its result groups by the secret's identity, and reuses that key for every
        # location the same secret was found in. It is a group id, not a per-result one, so
        # it is recorded here rather than in unique_id_from_tool.
        if result.get("id"):
            description.append(f"**Secret id:** {result['id']}")

        finding = Finding(
            title=f"Secret detected: {rule_name}",
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(str(result.get("severity")).lower(), "Medium"),
            file_path=source,
            line=start_line,
            vuln_id_from_tool=result.get("ruleId"),
            mitigation="Revoke and rotate the secret, then remove it from the source history.",
            static_finding=True,
            dynamic_finding=False,
        )
        # 2ms carries a CVSS score alongside the severity for the rules that define one.
        cvss_score = result.get("cvssScore")
        if cvss_score is not None:
            finding.cvssv3_score = cvss_score
        return finding
