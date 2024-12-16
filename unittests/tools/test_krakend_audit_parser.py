from dojo.models import Test
from dojo.tools.krakend_audit.parser import KrakenDAuditParser
from unittests.dojo_test_case import DojoTestCase


class TestKrakenDAuditParser(DojoTestCase):

    def test_parse_no_findings(self):
        with open("unittests/scans/krakend_audit/no_findings.json", encoding="utf-8") as testfile:
            parser = KrakenDAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with open("unittests/scans/krakend_audit/many_findings.json", encoding="utf-8") as testfile:
            parser = KrakenDAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertEqual("Enable TLS or use a terminator in front of KrakenD.", finding.mitigation)
