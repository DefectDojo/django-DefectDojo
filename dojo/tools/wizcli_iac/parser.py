import json

from dojo.tools.wizcli_common_parsers.parsers import WizcliParsers


class WizcliIaCParser:

    """Wizcli IaC Scan results in JSON file format."""

    def get_scan_types(self):
        return ["Wizcli IaC Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wizcli IaC Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wizcli IaC Scan results in JSON file format."

    def get_findings(self, filename, test):
        scan_data = filename.read()
        try:
            data = json.loads(scan_data.decode("utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        results = data.get("result", {})

        rule_matches = results.get("ruleMatches", None)
        if rule_matches:
            findings.extend(WizcliParsers.parse_rule_matches(rule_matches, test))

        secrets = results.get("secrets", None)
        if secrets:
            findings.extend(WizcliParsers.parse_secrets(secrets, test))

        return findings
