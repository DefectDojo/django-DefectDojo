import contextlib
import csv
import io
import json
import logging
import sys
from datetime import datetime

from dateutil import parser as date_parser

from dojo.models import SEVERITIES, Finding, Test
from dojo.tools.wizcli_common_parsers.parsers import WizcliParsers

logger = logging.getLogger(__name__)


class WizParserByTitle:

    """Parser the CSV where the "Title" field is the match for a finding title."""

    def parse_findings(self, test: Test, reader: csv.DictReader) -> list[Finding]:
        """
        Parse the CSV with the assumed format of the link below.

        test file: https://github.com/DefectDojo/django-DefectDojo/blob/master/unittests/scans/wiz/multiple_findings.csv
        """
        findings = []
        description_fields = [
            "Description",
            "Resource Type",
            "Resource external ID",
            "Subscription ID",
            "Project IDs",
            "Project Names",
            "Control ID",
            "Resource Name",
            "Resource Region",
            "Resource Status",
            "Resource Platform",
            "Resource OS",
            "Resource original JSON",
            "Issue ID",
            "Resource vertex ID",
            "Ticket URLs",
            "Note",
            "Due At",
            "Subscription Name",
            "Wiz URL",
            "Cloud Provider URL",
            "Resource Tags",
            "Kubernetes Cluster",
            "Kubernetes Namespace",
            "Container Service",
        ]
        # Iterate over the objects to create findings
        for row in reader:
            title = row.get("Title")
            severity = row.get("Severity")
            mitigation = row.get("Remediation Recommendation")
            description = ""
            status_dict = WizcliParsers.convert_status(row.get("Status", None))
            if status_dict.get("is_mitigated", False):
                # If the finding is mitigated, set the date to the mitigation date
                mitigated_timestamp = None

                if row.get("Resolved Time", None):
                    with contextlib.suppress(ValueError):
                        mitigated_timestamp = date_parser.parse(row.get("Resolved Time"))

                    if not mitigated_timestamp:
                        # other timestamps in the wiz scans are ISO8601
                        # but the Resolved Time is in a different format based on data we've seen
                        # example value: 2025-04-03 20:20:00.43042 +0000 UTC

                        resolved_time_string = row.get("Resolved Time")
                        resolved_time_string = resolved_time_string.replace(" UTC", "")
                        # need to use suppress as try-except ValueError doesn't work here for some reason

                        #   File "/usr/local/lib/python3.11/_strptime.py", line 352, in _strptime
                        #     raise ValueError("unconverted data remains: %s" %
                        # ValueError: unconverted data remains:  CET
                        with contextlib.suppress(ValueError):
                            mitigated_timestamp = datetime.strptime(
                                resolved_time_string, "%Y-%m-%d %H:%M:%S.%f %z",
                            )

                        if not mitigated_timestamp:
                            logger.warning(f"Unable to parse Resolved Time: {resolved_time_string}")

                    status_dict["mitigated"] = mitigated_timestamp

            # Iterate over the description fields to create the description
            for field in description_fields:
                if (field_value := row.get(field)) is not None and len(field_value) > 0:
                    description += f"**{field}**: {field_value}\n"
            # Create the finding object
            findings.append(
                Finding(
                    title=title,
                    description=description,
                    severity=severity.lower().capitalize(),
                    static_finding=False,
                    dynamic_finding=True,
                    mitigation=mitigation,
                    test=test,
                    **status_dict,
                ),
            )
        return findings


class WizParserByDetailedName:

    """Parser the CSV where the "DetailedName" and "Name" fields are the match for a finding title."""

    def parse_findings(self, test: Test, reader: csv.DictReader) -> list[Finding]:
        """
        Parse the CSV with the assumed format of the link below.

        test file: Coming soon!
        """
        findings = []
        description_fields = {
            "WizURL": "Wiz URL",
            "HasExploit": "Has Exploit",
            "HasCisaKevExploit": "Has Cisa Kev Exploit",
            "LocationPath": "Location Path",
            "Version": "Version",
            "DetectionMethod": "Detection Method",
            "Link": "Link",
            "Projects": "Projects",
            "AssetID": "Asset ID",
            "AssetName": "Asset Name",
            "AssetRegion": "Asset Region",
            "ProviderUniqueId": "Provider Unique Id",
            "CloudProviderURL": "Cloud Provider URL",
            "CloudPlatform": "Cloud Platform",
            "SubscriptionExternalId": "Subscription External Id",
            "SubscriptionId": "Subscription Id",
            "SubscriptionName": "Subscription Name",
            "ExecutionControllers": "Execution Controllers",
            "ExecutionControllersSubscriptionExternalIds": "Execution Controllers Subscription External Ids",
            "ExecutionControllersSubscriptionNames": "Execution Controllers Subscription Names",
            "OperatingSystem": "Operating System",
            "IpAddresses": "Ip Addresses",
        }
        mitigation_fields = {
            "LocationPath": "Location Path",
            "FixedVersion": "Fixed Version",
            "Remediation": "Remediation",
        }

        for row in reader:
            # Common fields
            vulnerability_id = row.get("Name")
            package_name = row.get("DetailedName")
            package_version = row.get("Version")
            severity = row.get("VendorSeverity")
            finding_id = row.get("ID")

            description = self._construct_string_field(description_fields, row)
            mitigation = self._construct_string_field(mitigation_fields, row)
            status_dict = WizcliParsers.convert_status(row.get("FindingStatus", None))
            # Create the finding object
            finding = Finding(
                title=f"{package_name}: {vulnerability_id}",
                description=description,
                mitigation=mitigation,
                severity=self._validate_severities(severity),
                static_finding=True,
                unique_id_from_tool=finding_id,
                component_name=package_name,
                component_version=package_version,
                date=date_parser.parse(row.get("FirstDetected")),
                test=test,
                **status_dict,
            )
            finding.unsaved_vulnerability_ids = [vulnerability_id]
            finding.unsaved_tags = self._parse_tags(row.get("Tags", "[]"))
            findings.append(finding)
        return findings

    def _construct_string_field(self, fields: dict[str, str], row: dict) -> str:
        """Construct a formatted string based on the fields dict supplied."""
        return_string = ""
        for field, pretty_field in fields.items():
            if (field_value := row.get(field)) is not None and len(field_value) > 0:
                return_string += f"**{pretty_field}**: `{field_value}`\n"
        return return_string

    def _parse_tags(self, tags: str) -> list[str]:
        """
        Parse the Tag string dict, and convert to a list of strings.

        The format of the tags is is "{""key"":""value""}" format
        """
        # Convert the string to a dict
        tag_dict = json.loads(tags)
        return [f"{key}: {value}" for key, value in tag_dict.items()]

    def _validate_severities(self, severity: str) -> str:
        """Ensure the supplied severity fits what DefectDojo is expecting."""
        if severity not in SEVERITIES:
            logger.error(f"Severity is not supported: {severity}")
            # Default to Info severity
            return "Info"
        return severity


class WizParser(
    WizParserByTitle,
    WizParserByDetailedName,
):
    def get_scan_types(self):
        return ["Wiz Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wiz Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wiz scan results in csv file format."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        # Determine which parser to use
        if "Title" in reader.fieldnames:
            return WizParserByTitle().parse_findings(test, reader)
        if all(field in reader.fieldnames for field in ["Name", "DetailedName"]):
            return WizParserByDetailedName().parse_findings(test, reader)
        msg = "This CSV format of Wiz is not supported"
        raise ValueError(msg)
