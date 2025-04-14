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
            self.assertEqual(5, len(findings))
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual("Informational", findings[0].severity)
            self.assertEqual("Domain: some-company.com", findings[0].title)
            self.assertIn("To prevent spam, email forgery and phishing, configure DKIM, DMARC, SPF DNS records for the domain if it is used to send or receive emails", findings[0].description)
            self.assertEqual(None, findings[0].unsaved_tags)
            self.assertEqual("some-company.com", findings[0].unsaved_endpoints[0].host)

            self.assertEqual("Informational", findings[1].severity)
            self.assertEqual("Web: aai.some-company.com", findings[1].title)
            self.assertIn("SSL/TLS encryption has not been detected when accessing your web application. SSL/TLS encryption is needed to protect the data transmitted between a user’s browser and a web server. It encrypts the data, preventing unauthorized access, helps to verify the identity of websites to protect against impersonation, and ensures data integrity so that it isn’t tampered with during transmission. Enable SSL/TLS encryption on your web application to ensure secure and private communication between your users and your application. This will protect sensitive data, build trust with your visitors, and help comply with security regulations.", findings[1].description)  # noqa: RUF001
            self.assertEqual(None, findings[1].unsaved_tags)
            self.assertEqual("aai.some-company.com", findings[1].unsaved_endpoints[0].host)

            self.assertEqual("Informational", findings[2].severity)
            self.assertEqual("Web: aai.some-company.com", findings[2].title)
            self.assertIn("Deploy a Web Application Firewall (WAF) to protect your website against common web attacks and malicious bots.", findings[2].description)
            self.assertEqual(None, findings[2].unsaved_tags)
            self.assertEqual("aai.some-company.com", findings[2].unsaved_endpoints[0].host)

            self.assertEqual("Informational", findings[4].severity)
            self.assertEqual("Data Leak: Stolen Credentials - 1.5 GB Corp Mails EU", findings[4].title)
            self.assertIn("Accounts of your employees are present in a stolen", findings[4].description)
            self.assertEqual(["Legacy"], findings[4].unsaved_tags)
            self.assertEqual([], findings[4].unsaved_endpoints)
            self.assertNotIn("mypassword1234", findings[4].description)
