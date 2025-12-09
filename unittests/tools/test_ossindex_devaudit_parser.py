from dojo.models import Test
from dojo.tools.ossindex_devaudit.parser import OssIndexDevauditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOssIndexDevauditParser(DojoTestCase):

    def test_ossindex_devaudit_parser_with_no_vulns_has_no_findings(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_no_vuln.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_ossindex_devaudit_parser_with_one_critical_vuln_has_one_finding(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_one_vuln.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_ossindex_devaudit_parser_with_multiple_vulns_has_multiple_finding(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_multiple_vulns.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertGreater(len(findings), 1)

    def test_ossindex_devaudit_parser_with_no_cve_returns_info_severity(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_vuln_no_cvssscore.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(len(findings), 1)

    def test_ossindex_devaudit_parser_with_reference_shows_reference(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_one_vuln.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        if len(findings) > 0:
            for item in findings:
                self.assertNotEqual(item.references, "")

    def test_ossindex_devaudit_parser_with_empty_reference_shows_empty_reference(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_empty_reference.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.references, "")

    def test_ossindex_devaudit_parser_with_missing_reference_shows_empty(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_missing_reference.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.references, "")

    def test_ossindex_devaudit_parser_with_missing_cwe_shows_1035(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_missing_cwe.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.cwe, 1035)

    def test_ossindex_devaudit_parser_with_null_cwe_shows_1035(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_null_cwe.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.cwe, 1035)

    def test_ossindex_devaudit_parser_with_empty_cwe_shows_1035(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_empty_cwe.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.cwe, 1035)

    def test_ossindex_devaudit_parser_get_severity_shows_info(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_severity_info.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.severity, "Info")

    def test_ossindex_devaudit_parser_get_severity_shows_critical(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_severity_critical.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.severity, "Critical")

    def test_ossindex_devaudit_parser_get_severity_shows_high(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_severity_high.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.severity, "High")

    def test_ossindex_devaudit_parser_get_severity_shows_medium(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_severity_medium.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.severity, "Medium")

    def test_ossindex_devaudit_parser_get_severity_shows_low(self):
        testfile = (
            get_unit_tests_scans_path("ossindex_devaudit") / "ossindex_devaudit_severity_low.json").open(encoding="utf-8",
        )
        parser = OssIndexDevauditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        if len(findings) > 0:
            for item in findings:
                self.assertEqual(item.severity, "Low")
