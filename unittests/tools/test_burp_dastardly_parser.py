
from dojo.models import Test
from dojo.tools.burp_dastardly.parser import BurpDastardlyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBurpParser(DojoTestCase):

    def test_burp_dastardly_multiple_findings(self):
        with (get_unit_tests_scans_path("burp_dastardly") / "many_findings.xml").open(encoding="utf-8") as test_file:
            parser = BurpDastardlyParser()
            findings = parser.get_findings(test_file, Test())
            self.validate_locations(findings)
            self.assertEqual(4, len(findings))
