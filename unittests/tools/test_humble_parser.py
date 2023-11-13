from dojo.tools.humble.parser import HumbleParser
from dojo.models import Test, Finding
from unittests.dojo_test_case import DojoTestCase


class TestHumbleParser(DojoTestCase):
    def test_hydra_parser_with_many_findings_has_many_findings(self):
        testfile = open("unittests/scans/humble/many_findings.json")
        parser = HumbleParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()