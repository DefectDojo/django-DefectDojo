from django.test import TestCase
from dojo.tools.zap.parser import WfuzzParser
from dojo.models import Test, Engagement, Product


class TestWfuzzParser(TestCase):

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/wfuzz/no_findingsjson")
        parser = WfuzzParser()
        findings = parser.get_findings(testfile, self.get_test())
        self.assertEqual(0, len(findings))
