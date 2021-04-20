from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.blackduck_component_risk.parser import \
    BlackduckComponentRiskParser


class TestBlackduckComponentRiskParser(TestCase):
    def test_blackduck_enhanced_zip_upload(self):
        testfile = open(path.join(path.dirname(__file__), "scans/blackduck_component_risk/blackduck_hub_component_risk.zip"))
        parser = BlackduckComponentRiskParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(12, len(findings))
