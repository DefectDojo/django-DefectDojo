import hashlib
import json
import re
from dojo.models import Finding


class AuditJSParser(object):
    """Parser for AuditJS Scan tool"""

    def get_scan_types(self):
        return ["AuditJS Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AuditJS Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AuditJS Scanning tool using SonaType OSSIndex database with JSON output format"

    # By default, we assume we are using CVSS Version 2.0 (AuditJS always specifies when it's V3)
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
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
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = dict()

        for dependency in data:
            # reading package name in format pkg:npm/PACKAGE_NAME@PACKAGE_VERSION
            if "coordinates" in dependency:
                file_path = dependency["coordinates"]
                component_name, component_version = file_path.split('/')[1].split('@')

            # Check if there are any vulnerabilities
            if dependency['vulnerabilities']:
                # Get vulnerability data from JSON and setup variables
                for vulnerability in dependency['vulnerabilities']:
                    unique_id_from_tool = title = description = cvss = cvssVector = cve = cvss_version = cwe = references = severity = None
                    if "id" in vulnerability:
                        unique_id_from_tool = vulnerability["id"]
                    if 'title' in vulnerability:
                        title = vulnerability['title']
                        # Find CWE in title in form "CWE-****"
                        cwe_find = re.findall(r"^CWE-[0-9]{1,4}", title)
                        if cwe_find:
                            cwe = int(cwe_find[0][4:])
                            # title = title.split(":")[1][1:] Unsure if AuditJS can specify both CWE and CVE at the same time
                    if 'description' in vulnerability:
                        description = vulnerability['description']
                    if 'cvssScore' in vulnerability:
                        cvss = vulnerability['cvssScore']
                    # CVSS Vector not always given
                    if 'cvssVector' in vulnerability:
                        # Find if CVSS Version is specfied
                        cvss_version = re.findall(r"^CVSS:[0-9]", vulnerability['cvssVector'])
                        if cvss_version:
                            severity = self.get_severity(cvss, vulnerability['cvssVector'][5:8])
                            # If it's version 3.0 and above
                            if vulnerability['cvssVector'][5] == "3":
                                cvssVector = vulnerability['cvssVector'][9:]
                                description = description + "\n\nCVSS V3 Vector: " + cvssVector
                        else:
                            severity = self.get_severity(cvss)
                            description = description + "\n\nCVSS Vector: " + vulnerability['cvssVector']
                    else:
                        # Calculated based on CVSS V2
                        severity = self.get_severity(cvss)
                    if 'cve' in vulnerability:
                        cve = vulnerability['cve']
                        # title = title.split(":")[1][1:]
                    if 'reference' in vulnerability:
                        references = vulnerability['reference']

                    finding = Finding(
                        title=title,
                        test=test,
                        cve=cve,
                        cwe=cwe,
                        cvssv3=cvssVector,
                        cvssv3_score=cvss,
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

                    # internal de-duplication
                    dupe_key = hashlib.sha256(str(unique_id_from_tool + title + description + component_version).encode('utf-8')).hexdigest()
                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                        if finding.description:
                            find.description += "\n" + finding.description
                        find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                        dupes[dupe_key] = find
                    else:
                        dupes[dupe_key] = finding

        return list(dupes.values())
