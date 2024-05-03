from os import path

from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.burp_enterprise.parser import BurpEnterpriseParser


class TestBurpEnterpriseParser(DojoTestCase):

    def test_burp_enterprise_with_multiple_vulns(self):
        with open(path.join(path.dirname(__file__), "../scans/burp_enterprise/many_vulns.html")) as test_file:
            parser = BurpEnterpriseParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(12, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.dynamic_finding)
                self.assertEqual(942, finding.cwe)
                self.assertEqual("Cross-origin resource sharing: arbitrary origin trusted", finding.title)
                description = """**Issue detail:**
The application implements an HTML5 cross-origin resource sharing (CORS) policy for this request that allows access from any domain.The application allowed access from the requested origin https://llqvfwgbsdau.com

"""
                self.assertEqual(description, finding.description)
                self.assertIn("An HTML5 cross-origin resource sharing (CORS) policy controls", finding.impact)
                self.assertIn("(Web Security Academy: Cross-origin resource sharing (CORS))[https://portswigger.net/web-security/cors]", finding.references)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                self.assertEqual("example.com", finding.unsaved_endpoints[0].host)

            with self.subTest(i=5):
                finding = findings[5]
                self.assertEqual("Info", finding.severity)
                self.assertTrue(finding.dynamic_finding)
                self.assertIsNone(finding.cwe)
                self.assertEqual("WAF Detected: redacted", finding.title)
                self.assertIn("WAF tech. details    : Cloud-based CDN, WAF & DDoS prevention", finding.description)
