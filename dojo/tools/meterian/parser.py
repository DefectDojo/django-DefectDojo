import json
from urllib.parse import urlparse

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
        report_json = self.parse_json(report)

        security_reports = report_json["reports"]["security"]["reports"]
        for single_security_report in security_reports:
            findings += self.do_get_findings(single_security_report, test)

        return findings

    def do_get_findings(self, single_security_report, test):
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
                        finding.cve = advisory["cve"]

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

    def uri_validator(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc, result.path])
        except:
            return False

    def get_reference_url(self, link_obj):
        maybe_url = link_obj["url"]

        if self.uri_validator(maybe_url):
            return maybe_url
        elif self.uri_validator(maybe_url) is False:
            if link_obj["type"] == "CVE":
                return "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + link_obj["url"]
            if link_obj["type"] == "NVD":
                return "https://nvd.nist.gov/vuln/detail/" + link_obj["url"]

        return None

    def parse_json(self, json_input):
        try:
            data = json_input.read()
            try:
                json_element = json.loads(str(data, 'utf-8'))
            except:
                json_element = json.loads(data)
        except:
            raise Exception("Invalid format")

        return json_element
