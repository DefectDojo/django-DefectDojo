from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.snyk_code.parser import SnykCodeParser


class TestSnykCodeParser(DojoTestCase):

    def test_snykParser_single_has_many_findings(self):
        testfile = open("unittests/scans/snyk_code/single_project_many_vulns.json")
        parser = SnykCodeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(206, len(findings))

    def test_snykcode_issue_9270(self):
        with open("unittests/scans/snyk_code/snykcode_issue_9270.json") as testfile:
            parser = SnykCodeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(39, len(findings))
