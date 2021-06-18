import datetime
from django.test import TestCase

from dojo.models import Test, Finding
from dojo.tools.sarif.parser import SarifParser


class TestSarifParser(TestCase):
    def common_checks(self, finding):
        self.assertLessEqual(len(finding.title), 250)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cve:
            self.assertIsInstance(finding.cve, str)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)
        self.assertEqual(True, finding.static_finding)  # by specification
        self.assertEqual(False, finding.dynamic_finding)  # by specification

    def test_example_report(self):
        testfile = open(
            "dojo/unittests/scans/sarif/DefectDojo_django-DefectDojo__2020-12-11_13 42 10__export.sarif"
        )
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(510, len(findings))
        item = findings[0]
        for finding in findings:
            self.common_checks(finding)

    def test_example2_report(self):
        testfile = open("dojo/unittests/scans/sarif/appendix_k.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual("collections/list.h", item.file_path)
        self.assertEqual(15, item.line)
        self.assertEqual("Critical", item.severity)
        self.assertEqual(
            "A variable was used without being initialized.", item.description
        )
        self.assertEqual(datetime.datetime(2016, 7, 16, 14, 19, 1, tzinfo=datetime.timezone.utc), item.date)
        for finding in findings:
            self.common_checks(finding)

    def test_example_k1_report(self):
        testfile = open("dojo/unittests/scans/sarif/appendix_k1.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_example_k2_report(self):
        testfile = open("dojo/unittests/scans/sarif/appendix_k2.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual(
            'Variable "count" was used without being initialized.', item.title
        )
        self.assertEqual("src/collections/list.cpp", item.file_path)
        self.assertEqual(15, item.line)
        self.assertEquals(
            "A variable was used without being initialized. This can result in runtime errors such as null reference exceptions.",
            item.description,
        )
        for finding in findings:
            self.common_checks(finding)

    def test_example_k3_report(self):
        testfile = open("dojo/unittests/scans/sarif/appendix_k3.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual(
            'The insecure method "Crypto.Sha1.Encrypt" should not be used.', item.title
        )
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_ms(self):
        """Report file come from Microsoft SARIF sdk on GitHub"""
        testfile = open("dojo/unittests/scans/sarif/SuppressionTestCurrent.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        item = findings[0]
        self.assertEqual("New suppressed result.", item.title)
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_semgrep(self):
        testfile = open(
            "dojo/unittests/scans/sarif/semgrepowasp-benchmark-sample.sarif"
        )
        test = Test()
        parser = SarifParser()
        findings = parser.get_findings(testfile, test)
        self.assertEqual(1768, len(findings))
        item = findings[0]
        self.assertEqual(
            "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02660.java",
            item.file_path,
        )
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_scanlift_dependency_check(self):
        testfile = open("dojo/unittests/scans/sarif/dependency_check.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(13, len(findings))
        # finding 0
        item = findings[0]
        self.assertEqual(
            "file:////src/.venv/lib/python3.9/site-packages/tastypie_swagger/static/tastypie_swagger/js/lib/handlebars-1.0.0.js",
            item.file_path,
        )
        # finding 6
        item = findings[6]
        self.assertEqual("CVE-2019-11358", item.title)
        self.assertEqual("Medium", item.severity)
        self.assertEqual("CVE-2019-11358", item.cve)
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_scanlift_bash(self):
        testfile = open("dojo/unittests/scans/sarif/bash-report.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(27, len(findings))
        # finding 0
        item = findings[0]
        self.assertEqual(
            "file:///home/damien/dd/docker/setEnv.sh",
            item.file_path,
        )
        self.assertIsNone(item.cve)
        self.assertEqual(datetime.datetime(2021, 3, 8, 15, 39, 40, tzinfo=datetime.timezone.utc), item.date)
        # finding 6
        item = findings[6]
        self.assertEqual(
            "Decimals are not supported. Either use integers only, or use bc or awk to compare.",
            item.title,
        )
        self.assertEqual("Info", item.severity)
        self.assertIsNone(item.cve)
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_taint_python(self):
        testfile = open("dojo/unittests/scans/sarif/taint-python-report.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(11, len(findings))
        # finding 0
        item = findings[0]
        self.assertEqual(
            "file:///home/damien/dd/dojo/tools/veracode/parser.py",
            item.file_path,
        )
        self.assertIsNone(item.cve)
        self.assertEqual(datetime.datetime(2021, 3, 8, 15, 46, 16, tzinfo=datetime.timezone.utc), item.date)
        # finding 2
        item = findings[2]
        self.assertEqual(
            "file:///home/damien/dd/dojo/tools/qualys_infrascan_webgui/parser.py",
            item.file_path,
        )
        self.assertEqual(169, item.line)
        # finding 6
        item = findings[6]
        self.assertEqual(
            "XML injection with user data from `filename in parser_helper.py:167` is used for parsing XML at `parser_helper.py:23`.",
            item.title,
        )
        self.assertEqual("Critical", item.severity)
        self.assertIsNone(item.cve)
        for finding in findings:
            self.common_checks(finding)

    def test_njsscan(self):
        """Generated with opensecurity/njsscan (https://github.com/ajinabraham/njsscan)"""
        testfile = open("dojo/unittests/scans/sarif/njsscan.sarif")
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        # finding 0
        finding = findings[0]
        self.assertEqual(
            "file:///src/index.js",
            finding.file_path,
        )
        self.assertIsNone(finding.cve)
        self.assertEqual(datetime.datetime(2021, 3, 23, 0, 10, 48, tzinfo=datetime.timezone.utc), finding.date)
        self.assertEqual(327, finding.cwe)
        # finding 1
        finding = findings[1]
        self.assertEqual(
            "file:///src/index.js",
            finding.file_path,
        )
        self.assertEqual(235, finding.line)
        self.assertEqual(datetime.datetime(2021, 3, 23, 0, 10, 48, tzinfo=datetime.timezone.utc), finding.date)
        self.assertEqual(798, finding.cwe)
        for finding in findings:
            self.common_checks(finding)
