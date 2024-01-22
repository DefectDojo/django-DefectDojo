from ..dojo_test_case import DojoTestCase
from dojo.tools.ms_defender.parser import MSDefenderParser
from dojo.models import Test


class TestSDefenderParser(DojoTestCase):

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/ms_defender/report_many_vulns.json")
        parser = MSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        finding = findings[2]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("CVE-5678-9887_wjeriowerjoiewrjoweirjeowij", finding.title)

    def test_parse_one_finding(self):
        testfile = open("unittests/scans/ms_defender/report_one_vuln.json")
        parser = MSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("CVE-1234-5678_fjweoifjewiofjweoifjeowifjowei", finding.title)
        self.assertEqual("CVE-1234-5678", finding.cve)

    def test_parse_no_finding(self):
        testfile = open("unittests/scans/ms_defender/report_no_vuln.json")
        parser = MSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parser_defender_zip(self):
        testfile = open("unittests/scans/ms_defender/defender.zip")
        parser = MSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        finding = findings[2]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("CVE-5678-9887_None_Other_wjeriowerjoiewrjoweirjeowij", finding.title)
        for endpoint in finding.unsaved_endpoints:
            endpoint.clean()
        self.assertEqual("1.1.1.1", finding.unsaved_endpoints[0].host)

    def test_parser_defender_wrong_machines_zip(self):
        testfile = open("unittests/scans/ms_defender/defender_wrong_machines.zip")
        parser = MSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        finding = findings[2]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("CVE-5678-9887_wjeriowerjoiewrjoweirjeowij", finding.title)

    def test_parser_defender_multiple_files_zip(self):
        testfile = open("unittests/scans/ms_defender/defender_multiple_files.zip")
        parser = MSDefenderParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(5, len(findings))
        finding = findings[4]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("CVE-5678-8888_None_Other_wjeriowerjoiewrjoweirjeowij", finding.title)
        for endpoint in finding.unsaved_endpoints:
            endpoint.clean()
        self.assertEqual("1.1.1.1", finding.unsaved_endpoints[0].host)
