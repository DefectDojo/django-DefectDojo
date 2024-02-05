from ..dojo_test_case import DojoTestCase
from dojo.tools.clair.parser import ClairParser


class TestClairParser(DojoTestCase):

    def test_no_findings_clair(self):
        my_file_handle = open("unittests/scans/clair/clair_empty.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_few_findings_clair(self):
        my_file_handle = open("unittests/scans/clair/clair_few_vuln.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(4, len(findings))

    def test_many_findings_clair(self):
        my_file_handle = open("unittests/scans/clair/clair_many_vul.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(35, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("http://people.ubuntu.com/~ubuntu-security/cve/CVE-2018-20839", finding.references)
        self.assertEqual("CVE-2018-20839 - (systemd, 237-3ubuntu10.29)", finding.title)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2018-20839", finding.unsaved_vulnerability_ids[0])

    def test_parse_no_content_no_findings_clairklar(self):
        my_file_handle = open("unittests/scans/clair/clairklar_empty.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_high_findings_clairklar(self):
        my_file_handle = open("unittests/scans/clair/clairklar_high.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(findings))

    def test_mixed_findings_clairklar(self):
        my_file_handle = open("unittests/scans/clair/clairklar_mixed.json")
        parser = ClairParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(6, len(findings))
