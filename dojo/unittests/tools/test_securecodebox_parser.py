from django.test import TestCase
from dojo.tools.securecodebox.parser import SecureCodeBoxParser
from dojo.models import Engagement, Product, Test


class TestSecureCodeBoxParser(TestCase):

    def get_test(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        return test

    def test_scb_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/securecodebox/scb_zero_vul.json")
        parser = SecureCodeBoxParser()
        findings = parser.get_findings(testfile, self.get_test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_scb_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/securecodebox/scb_one_vul.json")
        parser = SecureCodeBoxParser()
        findings = parser.get_findings(testfile, self.get_test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)
        self.assertEqual("473454f7-14b4-4014-8c2b-d0325b55234e",
                         findings[0].unique_id_from_tool)

    def test_scb_parser_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/securecodebox/scb_many_vul.json")
        parser = SecureCodeBoxParser()
        findings = parser.get_findings(testfile, self.get_test())
        testfile.close()
        self.assertEqual(5, len(findings))
        self.assertEqual(findings[0].severity, "Info")
        self.assertEqual(findings[0].title, "ssh")
        self.assertEqual(findings[0].description,
                         "Port 22 is open using tcp protocol.")
        self.assertEqual(findings[0].unique_id_from_tool,
                         "473454f7-14b4-4014-8c2b-d0325b55234e")
        self.assertEqual(
            findings[0].unsaved_endpoints[0].host, "scanme.nmap.org")
        self.assertEqual(findings[0].unsaved_endpoints[0].protocol, "tcp")
        self.assertEqual(findings[0].unsaved_endpoints[0].path, None)
        self.assertEqual(findings[0].unsaved_endpoints[0].query, None)
        self.assertEqual(findings[0].unsaved_endpoints[0].fragment, None)
        self.assertEqual(findings[0].unsaved_endpoints[0].port, 22)

    def test_scb_parser_with_many_vuln_has_many_findings_nikto(self):
        testfile = open(
            "dojo/unittests/scans/securecodebox/scb_many_vul_nikto.json")
        parser = SecureCodeBoxParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertEqual(101, len(findings))
        testfile.close()

    def test_scb_parser_handles_multiple_scan_types(self):
        # check that findings from multiple scanners can be parsed
        # includes wps, ssh and nikto scan
        testfile = open(
            "dojo/unittests/scans/securecodebox/scb_multiple_scans.json")
        parser = SecureCodeBoxParser()
        findings = parser.get_findings(testfile, self.get_test())
        testfile.close()
        self.assertEqual(3, len(findings))
        self.assertEqual(findings[0].title, "WordPress Service")
        self.assertEqual(findings[0].description,
                         "WordPress Service Information")
        self.assertEqual(findings[1].title, "SSH Service")
        self.assertEqual(findings[1].description, "SSH Service Information")
        self.assertEqual(
            findings[2].title, "The anti-clickjacking X-Frame-Options header is not present.")
        self.assertEqual(findings[2].description, "N/A")

    def test_scb_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context:
            testfile = open(
                "dojo/unittests/scans/securecodebox/empty_with_error.json")
            parser = SecureCodeBoxParser()
            findings = parser.get_findings(testfile, self.get_test())
            testfile.close()
