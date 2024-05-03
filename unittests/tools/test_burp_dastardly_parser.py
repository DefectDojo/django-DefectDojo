from os import path

from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.burp_dastardly.parser import BurpDastardlyParser


class TestBurpParser(DojoTestCase):

    def test_burp_dastardly_multiple_findings(self):
        with open(path.join(path.dirname(__file__), "../scans/burp_dastardly/many_findings.xml")) as test_file:
            parser = BurpDastardlyParser()
            findings = parser.get_findings(test_file, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(4, len(findings))
