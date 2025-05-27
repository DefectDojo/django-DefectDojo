import json
import re
from json.decoder import JSONDecodeError

# import cvss.parser
from cvss import CVSS2, CVSS3, CVSS4, CVSSError

from dojo.models import Finding


# TEMPORARY: Local implementation until the upstream PR is merged & released: https://github.com/RedHatProductSecurity/cvss/pull/75
def parse_cvss_from_text(text):
    """
    Parses CVSS2, CVSS3, and CVSS4 vectors from arbitrary text and returns a list of CVSS objects.

    Parses text for substrings that look similar to CVSS vector
    and feeds these matches to CVSS constructor.

    Args:
        text (str): arbitrary text

    Returns:
        A list of CVSS objects.

    """
    # Looks for substrings that resemble CVSS2, CVSS3, or CVSS4 vectors.
    # CVSS3 and CVSS4 vectors start with a 'CVSS:x.x/' prefix and are matched by the optional non-capturing group.
    # CVSS2 vectors do not include a prefix and are matched by raw vector pattern only.
    # Minimum total match length is 26 characters to reduce false positives.
    matches = re.compile(r"(?:CVSS:[3-4]\.\d/)?[A-Za-z:/]{26,}").findall(text)

    cvsss = set()
    for match in matches:
        try:
            if match.startswith("CVSS:4."):
                cvss = CVSS4(match)
            elif match.startswith("CVSS:3."):
                cvss = CVSS3(match)
            else:
                cvss = CVSS2(match)

            cvsss.add(cvss)
        except (CVSSError, KeyError):
            pass

    return list(cvsss)


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
                        cvss_vector
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
                    if "cvssVector" in vulnerability:
                        cvss_vectors = parse_cvss_from_text(
                            vulnerability["cvssVector"],
                        )

                        if len(cvss_vectors) > 0:
                            vector_obj = cvss_vectors[0]

                            if isinstance(vector_obj, CVSS4):
                                description += "\nCVSS V4 Vector:" + vector_obj.clean_vector()
                                severity = vector_obj.severities()[0]

                            elif isinstance(vector_obj, CVSS3):
                                cvss_vector = vector_obj.clean_vector()
                                severity = vector_obj.severities()[0]

                            elif isinstance(vector_obj, CVSS2):
                                description += "\nCVSS V2 Vector:" + vector_obj.clean_vector()
                                severity = vector_obj.severities()[0]

                            else:
                                msg = "Unsupported CVSS version detected in parser."
                                raise ValueError(msg)
                        else:
                            # Explicitly raise an error if no CVSS vectors are found,
                            # to avoid 'NoneType' errors during severity processing later.
                            msg = "No CVSS vectors found. Please check that parse_cvss_from_text() correctly parses the provided cvssVector."
                            raise ValueError(msg)
                    else:
                        # If there is no vector, calculate severity based on
                        # score and CVSS V3 (AuditJS does not always include
                        # it)
                        severity = self.get_severity(cvss_score)
                    if "cve" in vulnerability:
                        vulnerability_id = vulnerability["cve"]
                    if "reference" in vulnerability:
                        references = vulnerability["reference"]

                    finding = Finding(
                        title=title,
                        test=test,
                        cwe=cwe,
                        cvssv3=cvss_vector,
                        cvssv3_score=cvss_score,
                        description=description,
                        severity=severity,
                        references=references,
                        file_path=file_path,
                        component_name=component_name,
                        component_version=component_version,
                        static_finding=True,
                        dynamic_finding=False,
                        unique_id_from_tool=unique_id_from_tool,
                    )
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
