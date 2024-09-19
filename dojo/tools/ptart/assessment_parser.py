from datetime import datetime

from dojo.models import Finding, Endpoint, FileUpload


class PTARTAssessmentParser:
    def __init__(self):
        self.PTART_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

    def get_test_data(self, tree):
        if "assessments" in tree:
            assessments = tree["assessments"]
        else:
            raise ValueError("Parse Error: assessments key not found in the report")

        return [finding for assessment in assessments for finding in self.parse_assessment(assessment)]

    def parse_assessment(self, assessment):
        return [self.get_finding(assessment, hit) for hit in assessment.get("hits", [])]

    def get_finding(self, assessment, hit):
        finding = Finding(
            title=hit["title"],
            description=hit["body"],
            severity=self.parse_severity(hit["severity"]),
            mitigation=hit["remediation"],
            cvssv3=hit["cvss_vector"],
            unique_id_from_tool=hit["id"],
            effort_for_fixing=self.parse_fix_effort(hit["fix_complexity"]),
            component_name=assessment["title"],
            date=(datetime.strptime(hit["added"], self.PTART_DATETIME_FORMAT).date()),
            cwe=self.parse_cwe(hit),
        )

        finding.unsaved_tags=hit["labels"]

        endpoint = Endpoint.from_uri(hit["asset"])
        finding.unsaved_endpoints = [endpoint]

        finding.unsaved_files = [{
            "title": screenshot["caption"],
            "data": screenshot["screenshot"]["data"]
        } for screenshot in hit["screenshots"]]

        finding.unsaved_files.extend([{
            "title": attachment["title"],
            "data": attachment["data"]
        } for attachment in hit["attachments"]])

        return finding

    def parse_severity(self, severity):
        severity_mapping = {
            1: "Critical",
            2: "High",
            3: "Medium",
            4: "Low"
        }
        return severity_mapping.get(severity, "Info")  # Default severity

    def parse_fix_effort(self, effort):
        effort_mapping = {
            1: "High",
            2: "Medium",
            3: "Low"
        }
        return effort_mapping.get(effort, "")

    def parse_cwe(self, hit):
        top10mapping = {
            "A01:2021-Broken Access Control": 1345,
            "A02:2021-Cryptographic Failures": 1346,
            "A03:2021-Injection": 1347,
            "A04:2021-Insecure Design": 1348,
            "A05:2021-Security Misconfiguration": 1349,
            "A06:2021-Vulnerable and Outdated Components": 1352,
            "A07:2021-Identification and Authentication Failures": 1353,
            "A08:2021-Software and Data Integrity Failures": 1354,
            "A09:2021-Security Logging and Monitoring Failures": 1355,
            "A10:2021-Server-Side Request Forgery": 1356
        }
        if hit['labels']:
            return top10mapping.get(hit['labels'][0], None)
        else:
            return None
