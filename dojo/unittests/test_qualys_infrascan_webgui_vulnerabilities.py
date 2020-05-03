from django.test import TestCase
from dojo.models import Test
from dojo.tools.qualys_infrascan_webgui.parser import QualysInfraScanParser


class TestQualysInfraScanParser(TestCase):
    def test_parse_without_file_has_no_findings(self):
        parser = QualysInfraScanParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/qualys_infrascan_webgui/qualys_infrascan_webgui_0.xml")
        parser = QualysInfraScanParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    # Sample with One Test
    # + also verify data with one test
    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/qualys_infrascan_webgui/qualys_infrascan_webgui_1.xml")
        parser = QualysInfraScanParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

        findings = parser.items[0]
        self.assertEqual(findings.title, "Oracle Java SE Critical Patch Update - January 2015")
        self.assertEqual(
            findings.severity, "Critical"
        )  # Negligible is translated to Informational

    # Sample with Multiple Test
    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/qualys_infrascan_webgui/qualys_infrascan_webgui_multiple.xml")
        parser = QualysInfraScanParser(testfile, Test())
        self.assertEqual(6, len(parser.items))
