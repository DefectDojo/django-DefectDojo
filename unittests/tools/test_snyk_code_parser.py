from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.snyk_code.parser import SnykCodeParser


class TestSnykCodeParser(DojoTestCase):

    def test_snykcode_issue_9270(self):
        with open("unittests/scans/snyk/snykcode_issue_9270.json") as testfile:
            parser = SnykCodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(39, len(findings))
