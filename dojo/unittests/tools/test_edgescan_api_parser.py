import json

from django.test import TestCase

from dojo.tools.edgescan_api.parser import EdgescanApiParser, ES_SEVERITIES
from dojo.models import Test, Finding


class TestEdgescanApiParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open("dojo/unittests/scans/edgescan/no_vuln.json") as testfile:
            parser = EdgescanApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open("dojo/unittests/scans/edgescan/one_vuln.json") as testfile:
            parser = EdgescanApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            testfile.seek(0)
            payload = json.loads(testfile.read())[0]
            self.assertEqual(finding.title, payload["name"])
            self.assertEqual(finding.date, payload["date_opened"][:10])
            self.assertEqual(finding.cwe, int(payload["cwes"][0][4:]))
            self.assertEqual(finding.cve, str(payload["cves"]))
            self.assertEqual(finding.severity, ES_SEVERITIES[payload["severity"]])
            self.assertEqual(finding.description, payload["description"])
            self.assertEqual(finding.mitigation, payload["remediation"])
            self.assertEqual(finding.numerical_severity, Finding.get_numerical_severity(ES_SEVERITIES[payload["severity"]]))
            self.assertEqual(finding.vuln_id_from_tool, payload["id"])

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open("dojo/unittests/scans/edgescan/many_vulns.json") as testfile:
            parser = EdgescanApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            testfile.seek(0)
            payloads = json.loads(testfile.read())
            for i in range(2):
                finding = findings[i]
                payload = payloads[i]
                self.assertEqual(finding.title, payload["name"])
                self.assertEqual(finding.date, payload["date_opened"][:10])
                self.assertEqual(finding.cwe, int(payload["cwes"][0][4:]))
                self.assertEqual(finding.cve, str(payload["cves"]))
                self.assertEqual(finding.severity, ES_SEVERITIES[payload["severity"]])
                self.assertEqual(finding.description, payload["description"])
                self.assertEqual(finding.mitigation, payload["remediation"])
                self.assertEqual(finding.numerical_severity, Finding.get_numerical_severity(ES_SEVERITIES[payload["severity"]]))
                self.assertEqual(finding.vuln_id_from_tool, payload["id"])
