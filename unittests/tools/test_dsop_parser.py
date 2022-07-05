from ..dojo_test_case import DojoTestCase
from dojo.tools.dsop.parser import DsopParser

from dojo.models import Test


class TestDsopParser(DojoTestCase):
    def test_zero_findings(self):
        testfile = open("unittests/scans/dsop/zero_vuln.xlsx", "rb")
        parser = DsopParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEquals(len(findings), 0)

    def test_many_findings(self):
        testfile = open("unittests/scans/dsop/many_vuln.xlsx", "rb")
        parser = DsopParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEquals(len(findings), 4)
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-15587", finding.unsaved_vulnerability_ids[0])
