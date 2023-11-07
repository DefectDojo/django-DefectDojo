from ..dojo_test_case import DojoTestCase
from dojo.tools.api_msdefender.parser import ApiMSDefenderParser
from dojo.models import Test


class TestAPIMSDefenderAPIParser(DojoTestCase):

    def test_parse_many_findings(self):
        filelist = []
        vulnerabilities = open("unittests/scans/api_msdefender/report_many_vulns.json")
        filelist.append(vulnerabilities)
        machines = open("unittests/scans/api_msdefender/machines.json")
        filelist.append(machines)
        parser = ApiMSDefenderParser()
        findings = parser.get_findings(filelist, Test())
        self.assertEqual(4, len(findings))
        finding = findings[2]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("CVE-5678-9887_None_Other_wjeriowerjoiewrjoweirjeowij", finding.title)
        for endpoint in finding.unsaved_endpoints:
            endpoint.clean()
        self.assertEqual("wjeriowerjoiewrjoweirjeowij", finding.unsaved_endpoints[0].host)

    def test_parse_one_finding(self):
        filelist = []
        vulnerabilities = open("unittests/scans/api_msdefender/report_one_vuln.json")
        filelist.append(vulnerabilities)
        machines = open("unittests/scans/api_msdefender/machines.json")
        filelist.append(machines)
        parser = ApiMSDefenderParser()
        findings = parser.get_findings(filelist, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("CVE-1234-5678_afjweiofwejfio.com_plat_fjweoifjewiofjweoifjeowifjowei", finding.title)
        self.assertEqual("CVE-1234-5678", finding.cve)
        for endpoint in finding.unsaved_endpoints:
            endpoint.clean()
        self.assertEqual("fjweoifjewiofjweoifjeowifjowei", finding.unsaved_endpoints[0].host)

    def test_parse_no_finding(self):
        filelist = []
        vulnerabilities = open("unittests/scans/api_msdefender/report_no_vuln.json")
        filelist.append(vulnerabilities)
        machines = open("unittests/scans/api_msdefender/machines.json")
        filelist.append(machines)
        parser = ApiMSDefenderParser()
        findings = parser.get_findings(filelist, Test())
        self.assertEqual(0, len(findings))
