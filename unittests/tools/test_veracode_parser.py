import datetime

from ..dojo_test_case import DojoTestCase
from dojo.tools.veracode.parser import VeracodeParser
from dojo.models import Test


class TestVeracodeScannerParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open("unittests/scans/veracode/one_finding.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_many_findings_different_hash_code_different_unique_id(self):
        testfile = open("unittests/scans/veracode/many_findings_different_hash_code_different_unique_id.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(123, finding.cwe)
        self.assertEqual("catname", finding.title)
        self.assertFalse(finding.is_mitigated)
        self.assertEqual("sourcefilepathMyApp2.java", finding.file_path)
        self.assertEqual(2, finding.line)
        self.assertEqual("app-12345_issue-1", finding.unique_id_from_tool)
        finding = findings[1]
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.dynamic_finding)
        finding = findings[2]
        self.assertEqual("High", finding.severity)
        self.assertIsNone(finding.cwe)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-1234-1234", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("Vulnerable component: library:1234", finding.title)
        self.assertFalse(finding.is_mitigated)

    def test_parse_file_with_multiple_finding(self):
        testfile = open("unittests/scans/veracode/many_findings.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(123, finding.cwe)
        self.assertEqual("catname", finding.title)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.is_mitigated)
        self.assertEqual("sourcefilepathMyApp.java", finding.file_path)
        self.assertEqual(2, finding.line)
        self.assertEqual("app-1234_issue-1", finding.unique_id_from_tool)
        self.assertIn('sast', finding.unsaved_tags)
        finding = findings[1]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(456, finding.cwe)
        self.assertTrue(finding.dynamic_finding)
        self.assertIn('dast', finding.unsaved_tags)
        finding = findings[2]
        self.assertEqual("High", finding.severity)
        self.assertIsNone(finding.cwe)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-1234-1234", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("Vulnerable component: library:1234", finding.title)
        self.assertFalse(finding.is_mitigated)
        self.assertIn('sca', finding.unsaved_tags)
        finding = findings[3]
        self.assertEqual("High", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-5678-5678", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("Vulnerable component: library1:1234", finding.title)
        self.assertFalse(finding.is_mitigated)
        self.assertIn('sca', finding.unsaved_tags)

    def test_parse_file_with_multiple_finding2(self):
        testfile = open("unittests/scans/veracode/veracode_scan.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(7, len(findings))
        finding = findings[0]
        self.assertEqual("Information Exposure Through Sent Data", finding.title)
        self.assertEqual("Low", finding.severity)
        self.assertEqual(201, finding.cwe)
        self.assertEqual(datetime.datetime(2018, 2, 17, 0, 35, 18), finding.date)  # date_first_occurrence="2018-02-17 00:35:18 UTC"
        finding = findings[1]
        self.assertEqual("Low", finding.severity)
        self.assertEqual(201, finding.cwe)
        self.assertEqual("/devTools/utility.jsp", finding.file_path)
        self.assertEqual(361, finding.line)
        self.assertIsNone(finding.component_name)
        self.assertIsNone(finding.component_version)
        # finding 6
        finding = findings[6]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2012-6153", finding.unsaved_vulnerability_ids[0])
        self.assertEqual(20, finding.cwe)
        self.assertEqual("commons-httpclient", finding.component_name)
        self.assertEqual("3.1", finding.component_version)
        self.assertEqual(4.3, finding.cvssv3_score)

    def test_parse_file_with_mitigated_finding(self):
        testfile = open("unittests/scans/veracode/mitigated_finding.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.is_mitigated)
        self.assertEqual(datetime.datetime(2020, 6, 1, 10, 2, 1), finding.mitigated)
        self.assertEqual("app-1234_issue-1", finding.unique_id_from_tool)

    def test_parse_file_with_dynamic_finding(self):
        testfile = open("unittests/scans/veracode/dynamic_finding.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(456, finding.cwe)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual("catname", finding.title)
        self.assertEqual("Description", finding.description)
        self.assertFalse(finding.is_mitigated)
        self.assertEqual(datetime.datetime(2021, 9, 3, 10, 0, 0), finding.date)
        self.assertIn('dast', finding.unsaved_tags)
        self.assertEqual(1, len(finding.unsaved_endpoints))
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual('https', endpoint.protocol)
        self.assertEqual('www.example.com', endpoint.host)
        self.assertEqual('index.html', endpoint.path)

    def test_parse_file_with_changed_severity(self):
        testfile = open("unittests/scans/veracode/veracode_scan_changed_severity.xml")
        parser = VeracodeParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(7, len(findings))
        # finding 6
        finding = findings[6]
        self.assertEqual("Low", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2012-6153", finding.unsaved_vulnerability_ids[0])
        self.assertEqual(20, finding.cwe)
        self.assertEqual("commons-httpclient", finding.component_name)
        self.assertEqual("3.1", finding.component_version)
        self.assertEqual(4.3, finding.cvssv3_score)
