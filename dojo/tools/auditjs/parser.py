import json
import logging
import re
from json.decoder import JSONDecodeError

# import cvss.parser
from dojo.models import Finding
from dojo.utils import parse_cvss_data

logger = logging.getLogger(__name__)


class AuditJSParser:

    """Parser for AuditJS Scan tool"""

    def get_scan_types(self):
        return ["AuditJS Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AuditJS Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AuditJS Scanning tool using SonaType OSSIndex database with JSON output format"

    # Used only in the case we do not have CVSS Vector
    def get_severity(self, cvss):
        cvss = float(cvss)
        if cvss > 0 and cvss < 4:
            return "Low"
        if cvss >= 4 and cvss < 7:
            return "Medium"
        if cvss >= 7 and cvss < 9:
            return "High"
        if cvss >= 9:
            return "Critical"
        return "Informational"

    def get_findings(self, filename, test):
        try:
            data = json.load(filename)
        except JSONDecodeError:
            msg = "Invalid JSON format. Are you sure you used --json option ?"
            raise ValueError(msg)
        dupes = {}

        for dependency in data:
            # reading package name in format pkg:npm/PACKAGE_NAME@PACKAGE_VERSION
            # or pkg:npm/PACKAGE_SCOPE/PACKAGE_NAME@PACKAGE_VERSION
            if "coordinates" in dependency:
                file_path = dependency["coordinates"]
                file_path_splitted = file_path.split("/")
                pacakge_full_name = (
                    f"{file_path_splitted[1]}/{file_path_splitted[2]}"
                    if len(file_path_splitted) == 3
                    else file_path_splitted[1]
                )

                component_name, component_version = pacakge_full_name.split(
                    "@",
                )

            # Check if there are any vulnerabilities
            if dependency["vulnerabilities"]:
                # Get vulnerability data from JSON and setup variables
                for vulnerability in dependency["vulnerabilities"]:
                    unique_id_from_tool = (
                        title
                    ) = (
                        description
                    ) = (
                        cvss_score
                    ) = (
                        cvssv3
                    ) = (
                        cvssv4
                    ) = (
                        cvssv3_score
                    ) = (
                        cvssv4_score
                    ) = vulnerability_id = cwe = references = severity = None
                    # Check mandatory
                    if (
                        "id" in vulnerability
                        and "title" in vulnerability
                        and "description" in vulnerability
                    ):
                        unique_id_from_tool = vulnerability["id"]
                        title = vulnerability["title"]
                        description = vulnerability["description"]
                        # Find CWE in title in form "CWE-****"
                        cwe_find = re.findall(r"^CWE-[0-9]{1,4}", title)
                        if cwe_find:
                            cwe = int(cwe_find[0][4:])
                    else:
                        msg = "Missing mandatory attributes (id, title, description). Please check your report or ask community."
                        raise ValueError(msg)
                    if "cvssScore" in vulnerability:
                        cvss_score = vulnerability["cvssScore"]
                    cvss_data = parse_cvss_data(vulnerability.get("cvssVector"))
                    if cvss_data:
                        severity = cvss_data["severity"]
                        cvssv3 = cvss_data["cvssv3"]
                        cvssv4 = cvss_data["cvssv4"]
                        # The score in the report can be different from what the cvss library calulates
                        if cvss_data["major_version"] == 2:
                            description += "\nCVSS V2 Vector:" + cvss_data["cvssv2"] + " (Score: " + str(cvss_score) + ")"
                    else:
                        # If there is no vector, calculate severity based on CVSS score
                        severity = self.get_severity(cvss_score)
                    if "cve" in vulnerability:
                        vulnerability_id = vulnerability["cve"]
                    if "reference" in vulnerability:
                        references = vulnerability["reference"]

                    finding = Finding(
                        title=title,
                        test=test,
                        cwe=cwe,
                        description=description,
                        severity=severity,
                        cvssv3=cvssv3,
                        cvssv3_score=cvssv3_score,
                        cvssv4=cvssv4,
                        cvssv4_score=cvssv4_score,
                        references=references,
                        file_path=file_path,
                        component_name=component_name,
                        component_version=component_version,
                        static_finding=True,
                        dynamic_finding=False,
                        unique_id_from_tool=unique_id_from_tool,
                    )
                    logger.debug("Finding fields:")
                    for field, value in finding.__dict__.items():
                        logger.debug("  %s: %r", field, value)
                    if vulnerability_id:
                        finding.unsaved_vulnerability_ids = [vulnerability_id]

                    # internal de-duplication
                    dupe_key = unique_id_from_tool
                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                        if finding.description:
                            find.description += "\n" + finding.description
                        find.unsaved_endpoints.extend(
                            finding.unsaved_endpoints,
                        )
                        dupes[dupe_key] = find
                    else:
                        dupes[dupe_key] = finding

        return list(dupes.values())
