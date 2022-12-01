import json

from dojo.models import Finding

from .importer import BlackduckApiImporter

SCAN_TYPE_ID = 'BlackDuck API'


class BlackduckApiParser(object):
    """
    Import from Synopsys BlackDuck API /findings
    """

    def get_scan_types(self):
        return [SCAN_TYPE_ID]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_TYPE_ID

    def get_description_for_scan_types(self, scan_type):
        return "BlackDuck findings can be directly imported using the Synopsys BlackDuck API. An API Scan Configuration has to be setup in the Product."

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return SCAN_TYPE_ID

    def get_findings(self, file, test):
        if file is None:
            data = BlackduckApiImporter().get_findings(test)
        else:
            data = json.load(file)
        findings = []
        for entry in data:
            vulnerability_id = entry["vulnerabilityWithRemediation"]["vulnerabilityName"]
            component_name = entry["componentName"]
            component_version = entry["componentVersionName"]
            finding = Finding(
                test=test,
                title=f'{vulnerability_id} in {component_name}:{component_version}',
                description=entry["vulnerabilityWithRemediation"].get("description"),
                severity=entry["vulnerabilityWithRemediation"]["severity"].title(),
                component_name=component_name,
                component_version=component_version,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=entry["vulnerabilityWithRemediation"].get("vulnerabilityName"),
            )
            # get CWE
            if entry["vulnerabilityWithRemediation"].get("cweId"):
                cwe_raw = entry["vulnerabilityWithRemediation"]["cweId"].split("-")
                if len(cwe_raw) == 2 and cwe_raw[1].isdigit():
                    finding.cwe = int(cwe_raw[1])
            findings.append(finding)
        return findings
