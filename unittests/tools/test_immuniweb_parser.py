from dojo.models import Test
from dojo.tools.immuniweb.parser import ImmuniwebParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestImmuniwebParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open(get_unit_tests_scans_path("immuniweb") / "ImmuniWeb-0-vuln.xml", encoding="utf-8") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        with open(get_unit_tests_scans_path("immuniweb") / "ImmuniWeb-1-vuln.xml", encoding="utf-8") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(get_unit_tests_scans_path("immuniweb") / "ImmuniWeb-multiple-vuln.xml", encoding="utf-8") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertGreater(len(findings), 2)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_json(self):
        with open(get_unit_tests_scans_path("immuniweb") / "ImmuniWeb-multiple-vuln.json", encoding="utf-8") as testfile:
            parser = ImmuniwebParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings), 1)
            self.assertEqual("Informational", findings[0].severity)
            self.assertEqual("domain: some-company.com", findings[0].title)
            self.assertIn("To prevent spam, email forgery and phishing, configure DKIM, DMARC, SPF DNS records for the domain if it is used to send or receive emails", findings[0].description)
            self.assertIn("To prevent spam, email forgery and phishing, configure DKIM, DMARC, SPF DNS records for the domain if it is used to send or receive emails", findings[0].mitigation)
            self.assertEqual(None, findings[0].unsaved_tags)
            self.assertEqual("some-company.com", findings[0].unsaved_endpoints[0].host)
