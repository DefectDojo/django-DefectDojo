import json

from datetime import datetime
from dojo.models import Finding


class MeterianParser(object):

    def get_scan_types(self):
        return ["Meterian Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Meterian JSON report output file can be imported."

    def get_findings(self, report, test):
        findings = []

        report_json = json.load(report)
        security_reports = self.get_security_reports(report_json)
        scan_date = str(datetime.fromisoformat(report_json["timestamp"]).date())
        for single_security_report in security_reports:
            findings += self.do_get_findings(single_security_report, scan_date, test)

        return findings

    def get_security_reports(self, report_json):
        if "reports" in report_json:
            if "security" in report_json["reports"]:
                if "reports" in report_json["reports"]["security"]:
                    return report_json["reports"]["security"]["reports"]

        raise ValueError("Malformed report: the security reports are missing.")

    def do_get_findings(self, single_security_report, scan_date, test):
        findings = []
        language = single_security_report["language"]
        for dependency_report in single_security_report["reports"]:

            lib_name = dependency_report["dependency"]["name"]
            lib_ver = dependency_report["dependency"]["version"]
            finding_title = lib_name + ":" + lib_ver
            for advisory in dependency_report["advices"]:

                severity = self.get_severity(advisory)
                finding = Finding(
                    title=finding_title,
                    date=scan_date,
                    test=test,
                    severity=severity,
                    severity_justification="Issue severity of: **" + severity + "** from a base " +
                    "CVSS score of: **" + str(advisory.get('cvss')) + "**",
                    description=advisory['description'],
                    component_name=lib_name,
                    component_version=lib_ver,
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    impact=severity,
                    static_finding=True,
                    dynamic_finding=False,
                    file_path="Manifest file",
                    unique_id_from_tool=advisory['id'],
                    tags=[language]
                )

                if 'cve' in advisory:
                    if "N/A" != advisory["cve"]:
                        finding.unsaved_vulnerability_ids = [advisory["cve"]]

                if "cwe" in advisory:
                    finding.cwe = int(advisory["cwe"].replace("CWE-", ""))

                mitigation_msg = "## Remediation\n"
                safe_versions = dependency_report["safeVersions"]
                if "latestPatch" in safe_versions:
                    mitigation_msg += "Upgrade " + lib_name + " to version " + safe_versions["latestPatch"] + " or higher."
                elif "latestMinor" in safe_versions:
                    mitigation_msg += "Upgrade " + lib_name + " to version " + safe_versions["latestMinor"] + " or higher."
                elif "latestMajor" in safe_versions:
                    mitigation_msg += "Upgrade " + lib_name + " to version " + safe_versions["latestMajor"] + "."
                else:
                    mitigation_msg = "We were not able to provide a safe version for this library.\nYou should consider replacing this component as it could be an issue for the safety of your application."
                finding.mitigation = mitigation_msg

                references = ""
                for link in advisory["links"]:
                    ref_link = self.get_reference_url(link)
                    if ref_link is not None:
                        references += "- " + ref_link + "\n"
                if references != "":
                    finding.references = references

                findings.append(finding)

        return findings

    def get_severity(self, advisory):
        # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
        if 'cvss' in advisory:
            if advisory['cvss'] <= 3.9:
                severity = "Low"
            elif advisory['cvss'] >= 4.0 and advisory['cvss'] <= 6.9:
                severity = "Medium"
            elif advisory['cvss'] >= 7.0 and advisory['cvss'] <= 8.9:
                severity = "High"
            else:
                severity = "Critical"
        else:
            if advisory["severity"] == "SUGGEST" or advisory["severity"] == "NA" or advisory["severity"] == "NONE":
                severity = "Info"
            else:
                severity = advisory["severity"].title()

        return severity

    def get_reference_url(self, link_obj):
        url = link_obj["url"]
        if link_obj["type"] == "CVE":
            url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + link_obj["url"]
        elif link_obj["type"] == "NVD":
            url = "https://nvd.nist.gov/vuln/detail/" + link_obj["url"]

        return url
