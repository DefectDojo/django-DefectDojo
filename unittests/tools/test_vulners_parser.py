from ..dojo_test_case import DojoTestCase
from dojo.tools.vulners.parser import VulnersParser
from dojo.models import Test


class TestVulnersParser(DojoTestCase):

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/vulners/vulns_list.json")
        parser = VulnersParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(75, len(findings))


