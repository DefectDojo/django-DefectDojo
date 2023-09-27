import json
import dateutil
from dojo.models import Endpoint, Finding, Test

SEVERITY_MAPPING = {
    "INFORMATIONAL": "Info",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}

def is_private_ipv4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    # 10.0.0.0 to 10.255.255.255
    if parts[0] == '10':
        return True
    # 172.16.0.0 to 172.31.255.255
    if parts[0] == '172' and 16 <= int(parts[1]) <= 31:
        return True
    # 192.168.0.0 to 192.168.255.255
    if parts[0] == '192' and parts[1] == '168':
        return True
    return False

class AsffParser(object):
    def get_scan_types(self):
        return ["AWS Security Finding Format (ASFF) Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Security Finding Format (ASFF)"

    def get_description_for_scan_types(self, scan_type):
        return """AWS Security Finding Format (ASFF).
        https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html"""

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []

        for item in data:
            finding = Finding(
                title=item.get("Title"),
                description=item.get("Description"),
                date=dateutil.parser.parse(item.get("CreatedAt")),
                severity=self.get_severity(item.get("Severity")),
                active=(item.get("RecordState") == "ACTIVE"),
                unique_id_from_tool=item.get("Id"),
                test=test
            )

            if "Resources" in item:
                endpoints = []
                for resource in item["Resources"]:
                    if resource["Type"] == "AwsEc2Instance" and "Details" in resource:
                        details = resource["Details"]["AwsEc2Instance"]
                        for ip in details.get("IpV4Addresses", []):
                            if is_private_ipv4(ip):
                                endpoints.append(Endpoint(host=ip))
                finding.unsaved_endpoints = endpoints

            findings.append(finding)
        return findings

    def get_severity(self, data):
        if data.get("Label"):
            return SEVERITY_MAPPING[data.get("Label")]
        elif isinstance(data.get("Normalized"), int):
            if data.get("Normalized") > 89:
                return "Critical"
            elif data.get("Normalized") > 69:
                return "High"
            elif data.get("Normalized") > 39:
                return "Medium"
            elif data.get("Normalized") > 0:
                return "Low"
            else:
                return "Info"
        return None
