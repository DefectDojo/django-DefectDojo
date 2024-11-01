import json

import dateutil
from netaddr import IPAddress

from dojo.models import Endpoint, Finding

SEVERITY_MAPPING = {
    "INFORMATIONAL": "Info",  # No issue was found.
    "LOW": "Low",  # The issue does not require action on its own.
    "MEDIUM": "Medium",  # The issue must be addressed but not urgently.
    "HIGH": "High",  # The issue must be addressed as a priority.
    # The issue must be remediated immediately to avoid it escalating.
    "CRITICAL": "Critical",
}


class AsffParser:
    def get_scan_types(self):
        return ["AWS Security Finding Format (ASFF) Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Security Finding Format (ASFF)"

    def get_description_for_scan_types(self, scan_type):
        return """AWS Security Finding Format (ASFF).
        https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html"""

    def get_item_resource_arns(self, item):
        resource_arns = []
        if isinstance(item.get("Resources"), list):
            for resource_block in item["Resources"]:
                if isinstance(resource_block, dict):
                    resource_id = resource_block.get("Id")
                    if resource_id:
                        resource_arns.append(resource_id)
        return resource_arns

    def get_findings(self, file, test):
        data = json.load(file)
        result = []
        for item in data:
            if item.get("Remediation"):
                mitigation = item.get("Remediation").get("Recommendation").get("Text")
                references = item.get("Remediation").get("Recommendation").get("Url")
            else:
                mitigation = None
                references = None
            if item.get("RecordState") and item.get("RecordState") == "ACTIVE":
                active = True
            else:
                active = False

            # Adding the Resources:0/Id value to the description.
            #
            # This is needed because every Finding in AWS from Security Hub has an
            # associated ResourceId that contains the full AWS ARN and without it,
            # it is much more difficult to track down the specific resource.
            #
            # This is different from the Finding Id - as that is from the Security Hub
            # control and has no information about the offending resource.
            #
            # Retrieve the AWS ARN / Resource Id
            resource_arns = self.get_item_resource_arns(item)

            # Define the control_description
            control_description = item.get("Description")

            if resource_arns:
                resource_arn_strings = ", ".join(resource_arns)
                full_description = f"**AWS resource ARN:** {resource_arn_strings}\n\n{control_description}"
                impact = resource_arn_strings
            else:
                full_description = control_description
                impact = None

            finding = Finding(
                title=item.get("Title"),
                description=full_description,
                date=dateutil.parser.parse(item.get("CreatedAt")),
                mitigation=mitigation,
                references=references,
                severity=self.get_severity(item.get("Severity")),
                active=active,
                unique_id_from_tool=item.get("Id"),
                impact=impact,
            )

            if "Resources" in item:
                endpoints = []
                for resource in item["Resources"]:
                    if resource["Type"] == "AwsEc2Instance" and "Details" in resource:
                        details = resource["Details"]["AwsEc2Instance"]
                        for ip in details.get("IpV4Addresses", []):
                            # Adding only non-"global" IP addresses as endpoints:
                            #
                            # 1. **Stability**: In AWS, the private IP address of an EC2 instance remains consistent
                            #    unless the instance is terminated. In contrast, public IP addresses in AWS are separate
                            #    resources from the EC2 instances and can change (e.g., when an EC2 instance stops and starts).
                            #
                            # 2. **Reliability**: By focusing on private IP addresses, we reduce potential ambiguities.
                            #    If we were to include every IP address, DefectDojo would create an endpoint for each,
                            #    leading to potential redundancies and confusion.
                            #
                            # By limiting our endpoints to private IP addresses, we're ensuring that the data remains
                            # relevant even if the AWS resources undergo changes, and we also ensure a cleaner representation.
                            #
                            # netaddr deprecated the "is_private" method previously used here, so the logic has been
                            # flipped to exclude "global" addresses.
                            #
                            # Ref: https://netaddr.readthedocs.io/en/latest/api.html#netaddr.IPAddress.is_global
                            if not IPAddress(ip).is_global():
                                endpoints.append(Endpoint(host=ip))
                finding.unsaved_endpoints = endpoints

            result.append(finding)
        return result

    def get_severity(self, data):
        if data.get("Label"):
            return SEVERITY_MAPPING[data.get("Label")]
        if isinstance(data.get("Normalized"), int):
            # 0 - INFORMATIONAL
            # 1-39 - LOW
            # 40-69 - MEDIUM
            # 70-89 - HIGH
            # 90-100 - CRITICAL
            if data.get("Normalized") > 89:
                return "Critical"
            if data.get("Normalized") > 69:
                return "High"
            if data.get("Normalized") > 39:
                return "Medium"
            if data.get("Normalized") > 0:
                return "Low"
            return "Info"
        return None
