from django.test import TestCase
from dojo.tools.gitlab_dast.parser import GitlabDastParser
# from dojo.tools.{ cookiecutter.tool_name }}.parser import GitLab DAST ReportParser
from dojo.models import Test

"""
Scanner Confidence (Numerical):
    'Confirmed': 1,    # Certain
    'High': 3,         # Firm
    'Medium': 4,       # Firm
    'Low': 6,          # Tentative
    'Experimental': 7, # Tentative
    'Unknown': 8,      # Tentative
    'Ignore': 10,      # Tentative

Numerical Severity:
    'Critical': S0
    'High': S1
    'Medium': S2
    'Low': S3
    'Info': S4
    not above: S5
"""

class TestGitlabDastParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_dast/gitlab_dast_zero_vul.json")
        parser = GitlabDastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/gitlab_dast/gitlab_dast_one_vul.json")
        parser = GitlabDastParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]

        # endpoint validation
        for endpoint in finding.unsaved_endpoints:
            endpoint.clean()
        
        self.assertEqual("5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.unique_id_from_tool)
        self.assertEqual(3, finding.scanner_confidence)
        # vulnerability does not have a name: fallback to using id as a title
        self.assertEqual("5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.title)
        self.assertIsInstance(finding.description, str)

        date = finding.date.strftime("%Y-%m-%dT%H:%M:%S")
        self.assertEqual("2021-04-23T15:46:40", date)
        self.assertIsInstance(finding.references, str)

        # scanner = finding.found_by
        # self.assertEqual(scanner.name, f"id: zaproxy\nname: ZAProxy")
        # self.assertTrue(not scanner.static_tool)
        # self.assertTrue(scanner.dynamic_tool)
        
        self.assertEqual("High", finding.severity)
        self.assertEqual("S1", finding.numerical_severity)
        self.assertEqual("", finding.mitigation) # no solution proposed
        
        self.assertEqual(359, finding.cwe)
        self.assertEqual("10062", finding.cve)
        
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual("http", endpoint.protocol)
        self.assertEqual(80, endpoint.port)
        
    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_dast/gitlab_dast_many_vul.json")
        parser = GitlabDastParser()
        findings = parser.get_findings(testfile, Test())

        self.assertEqual(10, len(findings))

        # endpoint validation
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        
        # the first one is done above
        finding = findings[1]
        self.assertEqual("87e98ddf-7d75-444a-be6d-45400151a0fe", finding.unique_id_from_tool)
        self.assertEqual(3, finding.scanner_confidence)
        # vulnerability does not have a name: fallback to using id as a title
        self.assertEqual("87e98ddf-7d75-444a-be6d-45400151a0fe", finding.title)
        self.assertIsInstance(finding.description, str)

        date = finding.date.strftime("%Y-%m-%dT%H:%M:%S")
        self.assertEqual("2021-04-23T15:46:40", date)
        self.assertIsInstance(finding.references, str)

        # scanner = finding.found_by
        # self.assertEqual(scanner.name, f"id: zaproxy\nname: ZAProxy")
        # self.assertTrue(not scanner.static_tool)
        # self.assertTrue(scanner.dynamic_tool)

        self.assertEqual("Medium", finding.severity)
        self.assertEqual("S2", finding.numerical_severity)
        self.assertTrue("Ensure that your web server," in finding.mitigation)
        
        self.assertEqual(16, finding.cwe)
        self.assertEqual("10038", finding.cve)

        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual("http", endpoint.protocol)
        self.assertEqual(80, endpoint.port)
