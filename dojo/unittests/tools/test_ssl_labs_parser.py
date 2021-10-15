from django.test import TestCase
from dojo.tools.ssl_labs.parser import SslLabsParser
from dojo.models import Test


class TestSslLabsParser(TestCase):
    def test_parse_none(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/none.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(0, len(findings))

    def test_parse_ok(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_ok_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'A+' for defectdojo.mevitae.com")
        self.assertEqual(findings[0].url["host"], "defectdojo.mevitae.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Info")
        self.assertTrue("TLS" in findings[0].description)

    def test_parse_dh1024(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_dh1024_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'B' for dh1024.badssl.com")
        self.assertEqual(findings[0].url["host"], "dh1024.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Medium")
        self.assertTrue("TLS" in findings[0].description)

    def test_parse_3des(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_3des_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'C' for 3des.badssl.com")
        self.assertEqual(findings[0].url["host"], "3des.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "High")
        self.assertTrue("TLS" in findings[0].description)

    def test_parse_revoked(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_revoked_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'T' for revoked.badssl.com")
        self.assertEqual(findings[0].url["host"], "revoked.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Critical")
        self.assertTrue("TLS" in findings[0].description)

    def test_parse_multiple(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_multiple_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(3, len(findings))

        # Track the results we've found
        foundInfo = False
        foundMedium = False
        foundCritical = False

        for finding in findings:
            self.assertTrue("TLS" in finding.description)
            self.assertEqual(finding.cwe, 310)
            if finding.severity == "Info":
                self.assertEqual(finding.title, "TLS Grade 'A+' for defectdojo.mevitae.com")
                self.assertEqual(finding.url["host"], "defectdojo.mevitae.com")
                foundInfo = True
            elif finding.severity == "Medium":
                self.assertEqual(finding.title, "TLS Grade 'B' for dh1024.badssl.com")
                self.assertEqual(finding.url["host"], "dh1024.badssl.com")
                foundMedium = True
            elif finding.severity == "Critical":
                self.assertEqual(finding.title, "TLS Grade 'T' for revoked.badssl.com")
                self.assertEqual(finding.url["host"], "revoked.badssl.com")
                foundCritical = True
            else:
                self.fail("unexpected finding result")

        self.assertTrue(foundInfo and foundMedium and foundCritical)
