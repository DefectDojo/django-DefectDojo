from dojo.models import Finding
from .importer import MSDefenderApiImporter


class ApiMSDefenderParser(object):
    """
    Import from MSDefender API /findings
    """

    def get_scan_types(self):
        return ["MSDefender API"]

    def get_label_for_scan_types(self, scan_type):
        return "MSDefender API"

    def get_description_for_scan_types(self, scan_type):
        return ("MSDefender findings can be directly imported using the REST API")

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return "MSDefender API"

    def get_findings(self, file, test):
        findings = []
        report = MSDefenderApiImporter().get_findings(test)
        for vulnerability in report:
            description = ""
            description += "cveId: " + str(vulnerability['cveId']) + "\n"
            description += "machineId: " + str(vulnerability['machineId']) + "\n"
            description += "fixingKbId: " + str(vulnerability['fixingKbId']) + "\n"
            description += "productName: " + str(vulnerability['productName']) + "\n"
            description += "productVendor: " + str(vulnerability['productVendor']) + "\n"
            description += "productVersion: " + str(vulnerability['productVersion']) + "\n"
            finding = Finding(
                title=vulnerability["id"],
                severity=vulnerability['severity'],
                description=description,
                static_finding=False,
                dynamic_finding=True,
                vuln_id_from_tool=vulnerability["id"],
            )
            if vulnerability['fixingKbId'] is not None:
                finding.mitigation = vulnerability['fixingKbId']

            findings.append(finding)
        return findings
