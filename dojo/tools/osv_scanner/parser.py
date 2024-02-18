import json
from dojo.models import Finding


class OSVScannerParser(object):

    def get_scan_types(self):
        return ["OSV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OSV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "OSV scan output can be imported in JSON format (option --format json)."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = list
        finding = Finding(
            title="title",
            test=test,
            description="description",
            severity="High",
            static_finding=False,
            dynamic_finding=True,
        )
        findings.append(finding)
        return finding
