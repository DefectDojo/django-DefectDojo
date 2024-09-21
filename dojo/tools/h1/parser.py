import csv
import hashlib
import io
import json
from contextlib import suppress
from datetime import datetime
from typing import ClassVar

from dateutil import parser as date_parser
from django.core.files.uploadedfile import TemporaryUploadedFile

from dojo.models import Finding, Test

__author__ = "Kirill Gotsman"


class HackerOneVulnerabilityDisclosureProgram:
    """
    Vulnerability Disclosure Program HackerOne reports
    """

    def get_vulnerability_disclosure_json_findings(self, tree, test):
        """
        Converts a HackerOne reports to a DefectDojo finding
        """
        # Convert JSON  report to DefectDojo format
        dupes = {}
        for content in tree["data"]:
            # Get all relevant data
            date = content["attributes"]["created_at"]
            date = datetime.strftime(
                datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ"),
                "%Y-%m-%d",
            )
            # Build the title of the Dojo finding
            title = "#" + content["id"] + " " + content["attributes"]["title"]

            description = self.build_description(content)

            # References
            try:
                issue_tracker_id = content["attributes"]["issue_tracker_reference_id"]
                issue_tracker_url = content["attributes"]["issue_tracker_reference_url"]
                references = f"[{issue_tracker_id}]({issue_tracker_url})\n"
            except Exception:
                references = ""

            # Build the severity of the Dojo finding
            try:
                severity = content["relationships"]["severity"]["data"]["attributes"]["rating"].capitalize()
                if severity not in ["Low", "Medium", "High", "Critical"]:
                    severity = "Info"
            except Exception:
                severity = "Info"
            # Build the references of the Dojo finding
            ref_link = "https://hackerone.com/reports/{}".format(
                content.get("id"),
            )
            references += f"[{ref_link}]({ref_link})"

            # Set active state of the Dojo finding
            if content["attributes"]["state"] in ["triaged", "new"]:
                active = True
            else:
                active = False

            # Set CWE of the Dojo finding
            try:
                cwe = int(
                    content["relationships"]["weakness"]["data"]["attributes"]["external_id"][4:],
                )
            except Exception:
                cwe = 0

            dupe_key = hashlib.md5(
                str(references + title).encode("utf-8"),
            ).hexdigest()
            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.references:
                    finding.references = finding.references
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                # Build and return Finding model
                finding = Finding(
                    title=title,
                    unique_id_from_tool=dupe_key,
                    date=date,
                    test=test,
                    active=active,
                    description=description,
                    severity=severity,
                    mitigation="See description",
                    impact="No impact provided",
                    references=references,
                    cwe=cwe,
                    dynamic_finding=False,
                )
                finding.unsaved_endpoints = []
                dupes[dupe_key] = finding
        return list(dupes.values())

    def build_description(self, content):
        date = content["attributes"]["created_at"]
        date = datetime.strftime(
            datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "%Y-%m-%d",
        )
        reporter = content["relationships"]["reporter"]["data"]["attributes"]["username"]
        triaged_date = content["attributes"]["triaged_at"]

        # Build the description of the Dojo finding
        description = "#" + content["attributes"]["title"]
        description += f"\nSubmitted: {date}\nBy: {reporter}\n"

        # Add triaged date
        if triaged_date is not None:
            triaged_date = datetime.strftime(
                datetime.strptime(triaged_date, "%Y-%m-%dT%H:%M:%S.%fZ"),
                "%Y-%m-%d",
            )
            description += f"Triaged: {triaged_date}\n"

        # Try to grab CVSS
        try:
            cvss = content["relationships"]["severity"]["data"]["attributes"]["score"]
            description += f"CVSS: {cvss}\n"
        except Exception:
            pass

        # Build rest of description meat
        description += "##Report: \n{}\n".format(
            content["attributes"]["vulnerability_information"],
        )

        # Try to grab weakness if it's there
        try:
            weakness_title = content["relationships"]["weakness"]["data"]["attributes"]["name"]
            weakness_desc = content["relationships"]["weakness"]["data"]["attributes"]["description"]
            description += f"\n##Weakness: {weakness_title}\n{weakness_desc}"
        except Exception:
            pass

        return description


class HackerOneBugBountyProgram:
    """Bug Bounty Program HackerOne reports."""

    fields_to_label: ClassVar[dict[str, str]] = {
        "id": "ID",
        "weakness": "Weakness Category",
        "substate": "Substate",
        "reporter": "Reporter",
        "assigned": "Assigned To",
        "public": "Public",
        "triageted_at": "Triaged On",
        "closed_at": "Closed On",
        "awarded_at": "Awarded On",
        "bounty": "Bounty Price",
        "bonus": "Bonus",
        "first_response_at": "First Response On",
        "source": "Source",
        "reference": "Reference",
        "reference_url": "Reference URL",
        "structured_scope": "Structured Scope",
        "structured_scope_reference": "Structured Scope Reference",
        "original_report_id": "Original Report ID",
        "collaborating_users": "Collaboration Users",
        "duplicate_report_ids": "Duplicate Report IDs",
    }

    def get_bug_bounty_program_json_findings(self, dict_list: dict, test: Test) -> list[Finding]:
        return self.parse_findings(dict_list, test)

    def get_bug_bounty_program_csv_findings(self, dict_list: dict, test: Test) -> list[Finding]:
        return self.parse_findings(dict_list, test)

    def parse_findings(self, dict_list: list[dict], test: Test) -> list[Finding]:
        """Return a list of findings generated by the submitted report."""
        findings = []
        for entry in dict_list:
            status_dict = self.determine_status(entry)
            finding = Finding(
                title=entry.get("title"),
                severity=self.convert_severity(entry),
                description=self.parse_description(entry),
                date=date_parser.parse(entry.get("reported_at")),
                dynamic_finding=True,
                test=test,
                **status_dict,
            )
            # Add vulnerability IDs if they are present
            if (cve_str := entry.get("cve_ids")) is not None and len(cve_str) > 0:
                finding.unsaved_vulnerability_ids = [cve_str]
            # Add the finding the the list
            findings.append(finding)
        return findings

    def determine_status(self, row) -> dict:
        """Generate a dict of status meta to fully represent that state of the finding

        Possible states currently supported are open and closed. In the event that neither
        of those options are present, the open status will be the default, and returned
        """
        default_status = {
            "active": True,
        }
        # Open status -> active = True
        # Closed status -> is_mitigated = True + timestamp
        if (status := row.get("state")) is not None:
            if status == "open":
                return default_status
            if status == "closed":
                return {
                    "is_mitigated": True,
                    "active": False,
                    "mitigated": date_parser.parse(row.get("closed_at")),
                }
        return default_status

    def convert_severity(self, entry: dict) -> str:
        """Convert the severity from the parser from the string value, or CVSS score."""
        # Try to use the string severity first
        if (severity := entry.get("severity_rating")) is not None:
            if severity in ["critical", "high", "medium", "low"]:
                return severity.capitalize()
        # Fall back to "severity_score" which I assume is CVSS Score
        if (severity_score := entry.get("severity_score")) is not None:
            with suppress(ValueError):
                severity_score = float(severity_score)
                if severity_score >= 9.0:
                    return "Critical"
                if severity_score >= 7.0:
                    return "High"
                if severity_score >= 4.0:
                    return "Medium"
                if severity_score > 0.0:
                    return "Low"
        # Default to Info in all cases (assuming we reach this)
        return "Info"

    def parse_description(self, entry: dict) -> str:
        """Build the description from the mapping set in the fields_to_label var."""
        # Iterate over the items and build the string
        description = ""
        for field, label in self.fields_to_label.items():
            if (value := entry.get(field)) is not None and len(value) > 0:
                description += f"**{label}**: {value}\n"
        return description


class H1Parser(
    HackerOneVulnerabilityDisclosureProgram,
    HackerOneBugBountyProgram,
):
    """
    A class that can be used to parse the Get All Reports JSON export from HackerOne API.
    """

    def get_scan_types(self):
        return ["HackerOne Cases"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import HackerOne cases findings in JSON format."

    def get_findings(self, file: TemporaryUploadedFile, test: Test) -> list[Finding]:
        """Return the list of findings generated from the uploaded report."""
        # first determine which format to pase
        file_name = file.name
        if str(file_name).endswith(".json"):
            return self.determine_json_format(file, test)
        elif str(file_name).endswith(".csv"):
            return self.determine_csv_format(file, test)
        else:
            msg = "Filename extension not recognized. Use .json or .csv"
            raise ValueError(msg)

    def get_json_tree(self, file: TemporaryUploadedFile) -> dict:
        """Extract the CSV file into a iterable that represents a dict."""
        data = file.read()
        try:
            tree = json.loads(str(data, "utf-8"))
        except Exception:
            tree = json.loads(data)
        return tree

    def determine_json_format(self, file: TemporaryUploadedFile, test: Test) -> list[Finding]:
        """Evaluate the format of the JSON report that was uploaded to determine which parser to use."""
        tree = self.get_json_tree(file)
        # Check for some root elements
        if "findings" in tree:
            return self.get_bug_bounty_program_json_findings(tree.get("findings", []), test)
        if "data" in tree:
            return self.get_vulnerability_disclosure_json_findings(tree, test)
        else:
            msg = "This JSON format is not supported"
            raise ValueError(msg)

    def get_csv_reader(self, file: TemporaryUploadedFile) -> csv.DictReader:
        """Extract the CSV file into a iterable that represents a dict."""
        if file is None:
            return ()
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')

    def determine_csv_format(self, file: TemporaryUploadedFile, test: Test) -> list[Finding]:
        """Evaluate the format of the CSV report that was uploaded to determine which parser to use."""
        reader = self.get_csv_reader(file)
        # Check for some root elements
        if "bounty" in reader.fieldnames:
            return self.get_bug_bounty_program_csv_findings(reader, test)
        else:
            msg = "This CSV format is not supported"
            raise ValueError(msg)
