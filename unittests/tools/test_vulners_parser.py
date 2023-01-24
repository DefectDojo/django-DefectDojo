from ..dojo_test_case import DojoTestCase
from dojo.tools.vulners.parser import VulnersParser
from dojo.models import Test


class TestVulnersParser(DojoTestCase):

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/vulners/report_many_vulns.json")
        parser = VulnersParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        finding = findings[2]
        self.assertEqual("High", finding.severity)
        self.assertEqual("223.234.234.123", finding.unsaved_endpoints[0].host)
        self.assertEqual("VNS/CESA-2021:0348", finding.vuln_id_from_tool)
        self.assertEqual("**CentOS Errata and Security Advisory** CESA-2021:0348", finding.description)
        self.assertEqual(4, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", finding.cvssv3)

    def test_parse_one_finding(self):
        testfile = open("unittests/scans/vulners/report_one_vuln.json")
        parser = VulnersParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("12.34.56.78", finding.unsaved_endpoints[0].host)
        self.assertEqual("VNS/RHSA-2018:2285", finding.vuln_id_from_tool)
        self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)

    def test_parse_no_finding(self):
        testfile = open("unittests/scans/vulners/report_no_vulns.json")
        parser = VulnersParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_no_description(self):
        testfile = open("unittests/scans/vulners/report_no_description.json")
        parser = VulnersParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("12.34.56.78", finding.unsaved_endpoints[0].host)
        self.assertEqual("VNS/RHSA-2018:2285", finding.vuln_id_from_tool)
        self.assertEqual(finding.title, finding.description)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
