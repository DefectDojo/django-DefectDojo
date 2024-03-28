import json
from dojo.tools.awssecurityhub.inspector import Inspector
from dojo.tools.awssecurityhub.guardduty import GuardDuty
from dojo.tools.awssecurityhub.compliance import Compliance


class AwsSecurityHubParser(object):

    def get_scan_types(self):
        return ["AWS Security Hub Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Security Hub Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AWS Security Hub exports in JSON format."

    def get_findings(self, filehandle, test):
        tree = json.load(filehandle)
        if not isinstance(tree, dict):
            raise TypeError("Incorrect Security Hub report format")
        return self.get_items(tree, test)

    def get_items(self, tree: dict, test):
        items = {}
        findings = tree.get("Findings", tree.get("findings", None))
        if not isinstance(findings, list):
            raise TypeError("Incorrect Security Hub report format")
        for node in findings:
            aws_scanner_type = node.get("ProductFields", {}).get("aws/securityhub/ProductName", "")
            if aws_scanner_type == "Inspector":
                item = Inspector().get_item(node, test)
            elif aws_scanner_type == "GuardDuty":
                item = GuardDuty().get_item(node, test)
            else:
                item = Compliance().get_item(node, test)
            key = node["Id"]
            if not isinstance(key, str):
                raise TypeError("Incorrect Security Hub report format")
            items[key] = item
        return list(items.values())
