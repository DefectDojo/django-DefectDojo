import os.path

from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.trustwave.parser import TrustwaveParser
from dojo.models import Test, Engagement, Product


def sample_path(file_name):
    return os.path.join(get_unit_tests_path() + "/scans/trustwave", file_name)


class TestTrustwaveParser(DojoTestCase):

    def test_no_vuln(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        test_file = open(sample_path("many_vulns.csv"))
        parser = TrustwaveParser()
        findings = parser.get_findings(test_file, test)
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(len(findings), 4)
        # finding 0
        finding = findings[0]
        self.assertEqual("High", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-3011-123", finding.unsaved_vulnerability_ids[0])
        # finding 1
        finding = findings[1]
        self.assertEqual("Tom and Jerry  vulnerable to Mouse Traps", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-3011-321", finding.unsaved_vulnerability_ids[0])
        self.assertEqual(1, len(finding.unsaved_endpoints))
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual("192.168.0.58", endpoint.host)
        self.assertEqual("tcp", endpoint.protocol)
        self.assertEqual(80, endpoint.port)
        # finding 2
        finding = findings[2]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-3011-313", finding.unsaved_vulnerability_ids[0])
        # finding 3
        finding = findings[3]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-3011-32", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("Tom and Jerry versions 4 and 5 is vulnerable to Denial of Service (DoS) remote attack via the ever so long running series the simpsons", finding.description)
        self.assertEqual("This vulnerability was addressed in Tom and Jerry Reboot 12.0 Affected users should upgrade to the latest stable version of Tom and Jerry.", finding.mitigation)
        self.assertEqual(1, len(finding.unsaved_endpoints))
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual("www.example43.com", endpoint.host)
        self.assertEqual("tcp", endpoint.protocol)
        self.assertEqual(443, endpoint.port)
