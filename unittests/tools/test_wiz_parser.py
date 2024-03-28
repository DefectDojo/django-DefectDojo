from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.wiz.parser import WizParser


class TestWizParser(DojoTestCase):
    def test_no_findings(self):
        testfile = open("unittests/scans/wiz/no_findings.csv")
        parser = WizParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(0, len(findings))

    def test_one_findings(self):
        testfile = open("unittests/scans/wiz/one_finding.csv")
        parser = WizParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("AKS role/cluster role assigned permissions that contain wildcards ", finding.title)
        self.assertEqual("Informational", finding.severity)

    def test_multiple_findings(self):
        testfile = open("unittests/scans/wiz/multiple_findings.csv")
        parser = WizParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(98, len(findings))
        finding = findings[0]
        self.assertEqual("AKS role/cluster role assigned permissions that contain wildcards ", finding.title)
        self.assertEqual("Informational", finding.severity)
        finding = findings[1]
        self.assertEqual("Unusual activity by a principal from previously unseen country", finding.title)
        self.assertEqual("High", finding.severity)
        finding = findings[20]
        self.assertEqual("User/service account with get/list/watch permissions on secrets in an AKS cluster", finding.title)
        self.assertEqual("Informational", finding.severity)
