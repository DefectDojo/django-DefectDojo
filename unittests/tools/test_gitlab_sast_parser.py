from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.gitlab_sast.parser import GitlabSastParser
from dojo.models import Test


class TestGitlabSastParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-0-vuln.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding_v14(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-1-vuln_v14.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_one_vuln_has_one_finding_v15(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-1-vuln_v15.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_v14(self):
        with open(f"{get_unit_tests_path()}/scans/gitlab_sast/gl-sast-report-many-vuln_v14.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertTrue(3, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[1]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[2]
        self.assertEqual("PKCS8 key", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_v15(self):
        with open(f"{get_unit_tests_path()}/scans/gitlab_sast/gl-sast-report-many-vuln_v15.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertTrue(3, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[1]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[2]
        self.assertEqual("PKCS8 key", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_various_confidences_v14(self):
        with open(f"{get_unit_tests_path()}/scans/gitlab_sast/gl-sast-report-confidence_v14.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 8)
        for item in findings:
            self.assertTrue(item.cwe is None or isinstance(item.cwe, int))
        finding = findings[3]
        self.assertEqual("Tentative", finding.get_scanner_confidence_text())
        finding = findings[4]
        self.assertEqual("Tentative", finding.get_scanner_confidence_text())
        finding = findings[5]
        self.assertEqual("Firm", finding.get_scanner_confidence_text())
        finding = findings[6]
        self.assertEqual("Firm", finding.get_scanner_confidence_text())
        finding = findings[7]
        self.assertEqual("Certain", finding.get_scanner_confidence_text())

    def test_parse_file_with_various_confidences_v15(self):
        with open(f"{get_unit_tests_path()}/scans/gitlab_sast/gl-sast-report-confidence_v15.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 8)
        for item in findings:
            self.assertTrue(item.cwe is None or isinstance(item.cwe, int))
        finding = findings[3]
        self.assertEqual("", finding.get_scanner_confidence_text())
        finding = findings[4]
        self.assertEqual("", finding.get_scanner_confidence_text())
        finding = findings[5]
        self.assertEqual("", finding.get_scanner_confidence_text())
        finding = findings[6]
        self.assertEqual("", finding.get_scanner_confidence_text())
        finding = findings[7]
        self.assertEqual("", finding.get_scanner_confidence_text())

    def test_parse_file_with_various_cwes_v14(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-cwe_v14.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 3)
        self.assertEqual(79, findings[0].cwe)
        self.assertEqual(89, findings[1].cwe)
        self.assertEqual(None, findings[2].cwe)

    def test_parse_file_with_various_cwes_v15(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-cwe_v15.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 3)
        self.assertEqual(79, findings[0].cwe)
        self.assertEqual(89, findings[1].cwe)
        self.assertEqual(None, findings[2].cwe)

    def test_parse_file_issue4336_v14(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report_issue4344_v14.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("[None severity] Potential XSS vulnerability", finding.title)

    def test_parse_file_issue4336_v15(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report_issue4344_v15.json") as testfile:
            parser = GitlabSastParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("[None severity] Potential XSS vulnerability", finding.title)

    def test_without_scan_v14(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-1-vuln_v14.json") as testfile:
            parser = GitlabSastParser()
            tests = parser.get_tests(None, testfile)
        self.assertEqual(1, len(tests))
        test = tests[0]
        self.assertIsNone(test.name)
        self.assertIsNone(test.type)
        self.assertIsNone(test.version)
        findings = test.findings
        self.assertEqual(1, len(findings))

    def test_without_scan_v15(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-1-vuln_v15.json") as testfile:
            parser = GitlabSastParser()
            tests = parser.get_tests(None, testfile)
        self.assertEqual(1, len(tests))
        test = tests[0]
        self.assertIsNone(test.name)
        self.assertIsNone(test.type)
        self.assertIsNone(test.version)
        findings = test.findings
        self.assertEqual(1, len(findings))

    def test_with_scan_v14(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-confidence_v14.json") as testfile:
            parser = GitlabSastParser()
            tests = parser.get_tests(None, testfile)
        self.assertEqual(1, len(tests))
        test = tests[0]
        self.assertEqual("njsscan", test.name)
        self.assertEqual("njsscan", test.type)
        self.assertEqual("0.1.9", test.version)
        findings = test.findings
        self.assertEqual(8, len(findings))

    def test_with_scan_v15(self):
        with open("unittests/scans/gitlab_sast/gl-sast-report-confidence_v15.json") as testfile:
            parser = GitlabSastParser()
            tests = parser.get_tests(None, testfile)
        self.assertEqual(1, len(tests))
        test = tests[0]
        self.assertEqual("njsscan", test.name)
        self.assertEqual("njsscan", test.type)
        self.assertEqual("0.1.9", test.version)
        findings = test.findings
        self.assertEqual(8, len(findings))
