import json
from json.decoder import JSONDecodeError
import re
from dojo.models import Finding
from cvss import CVSS3, CVSS2
import cvss.parser


class AuditJSParser(object):
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
        elif cvss >= 4 and cvss < 7:
            return "Medium"
        elif cvss >= 7 and cvss < 9:
            return "High"
        elif cvss >= 9:
            return "Critical"
        else:
            return "Informational"

    def get_findings(self, filename, test):
        try:
            data = json.load(filename)
        except JSONDecodeError:
            raise ValueError("Invalid JSON format. Are you sure you used --json option ?")
        dupes = dict()

        for dependency in data:
            # reading package name in format pkg:npm/PACKAGE_NAME@PACKAGE_VERSION
            # or pkg:npm/PACKAGE_SCOPE/PACKAGE_NAME@PACKAGE_VERSION
            if "coordinates" in dependency:
                file_path = dependency["coordinates"]
                file_path_splitted = file_path.split("/")
                pacakge_full_name = f'{file_path_splitted[1]}/{file_path_splitted[2]}' if len(file_path_splitted) == 3 else file_path_splitted[1]

                component_name, component_version = pacakge_full_name.split('@')

            # Check if there are any vulnerabilities
            if dependency['vulnerabilities']:
                # Get vulnerability data from JSON and setup variables
                for vulnerability in dependency['vulnerabilities']:
                    unique_id_from_tool = title = description = cvss_score = cvss_vector = vulnerability_id = cwe = references = severity = None
                    # Check mandatory
                    if "id" in vulnerability and 'title' in vulnerability and 'description' in vulnerability:
                        unique_id_from_tool = vulnerability["id"]
                        title = vulnerability['title']
                        description = vulnerability['description']
                        # Find CWE in title in form "CWE-****"
                        cwe_find = re.findall(r"^CWE-[0-9]{1,4}", title)
                        if cwe_find:
                            cwe = int(cwe_find[0][4:])
                    else:
                        raise ValueError("Missing mandatory attributes (id, title, description). Please check your report or ask community.")
                    if 'cvssScore' in vulnerability:
                        cvss_score = vulnerability['cvssScore']
                    if 'cvssVector' in vulnerability:
                        cvss_vectors = cvss.parser.parse_cvss_from_text(vulnerability['cvssVector'])
                        if len(cvss_vectors) > 0 and type(cvss_vectors[0]) == CVSS3:
                            # Only set finding vector if it's version 3
                            cvss_vector = cvss_vectors[0].clean_vector()
                            severity = cvss_vectors[0].severities()[0]
                        elif len(cvss_vectors) > 0 and type(cvss_vectors[0]) == CVSS2:
                            # Otherwise add it to description
                            description = description + "\nCVSS V2 Vector:" + cvss_vectors[0].clean_vector()
                            severity = cvss_vectors[0].severities()[0]
                    else:
                        # If there is no vector, calculate severity based on score and CVSS V3 (AuditJS does not always include it)
                        severity = self.get_severity(cvss_score)
                    if 'cve' in vulnerability:
                        vulnerability_id = vulnerability['cve']
                    if 'reference' in vulnerability:
                        references = vulnerability['reference']

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
                        find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                        dupes[dupe_key] = find
                    else:
                        dupes[dupe_key] = finding

        return list(dupes.values())
