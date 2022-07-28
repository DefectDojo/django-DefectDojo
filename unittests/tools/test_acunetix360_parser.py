from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.acunetix360.parser import Acunetix360Parser
from datetime import datetime


class TestAcunetix360Parser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open("unittests/scans/acunetix360/acunetix360_one_finding.json")
        parser = Acunetix360Parser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(16, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")
            self.assertEqual(finding.date, datetime(2021, 6, 16, 12, 30))

    def test_parse_file_with_one_finding_false_positive(self):
        testfile = open("unittests/scans/acunetix360/acunetix360_one_finding_false_positive.json")
        parser = Acunetix360Parser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(16, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")
            self.assertTrue(finding.false_p)

    def test_parse_file_with_one_finding_risk_accepted(self):
        testfile = open("unittests/scans/acunetix360/acunetix360_one_finding_accepted_risk.json")
        parser = Acunetix360Parser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(16, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")
            self.assertTrue(finding.risk_accepted)

    def test_parse_file_with_multiple_finding(self):
        testfile = open("unittests/scans/acunetix360/acunetix360_many_findings.json")
        parser = Acunetix360Parser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(16, len(findings))
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(16, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(89, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://php.testsparker.com/artist.php?id=-1%20OR%2017-7=10")

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(205, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:H/RL:O/RC:C", finding.cvssv3)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://php.testsparker.com")

    def test_parse_file_with_mulitple_cwe(self):
        testfile = open("unittests/scans/acunetix360/acunetix360_multiple_cwe.json")
        parser = Acunetix360Parser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(16, finding.cwe)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual(str(endpoint), "http://php.testsparker.com/auth/login.php")
