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
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Info")
        self.assertTrue("TLS" in findings[0].description)

    def test_parse_dh1024(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_dh1024_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'B' for dh1024.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Medium")
        self.assertTrue("TLS" in findings[0].description)

    def test_parse_3des(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_3des_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'C' for 3des.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "High")
        self.assertTrue("TLS" in findings[0].description)

    def test_parse_revoked(self):
        parser = SslLabsParser()
        with open("dojo/unittests/scans/ssl_labs/ssl_labs_revoked_v1.5.0.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(findings[0].title, "TLS Grade 'T' for revoked.badssl.com")
        self.assertEqual(findings[0].cwe, 310)
        self.assertEqual(findings[0].severity, "Critical")
        self.assertTrue("TLS" in findings[0].description)
