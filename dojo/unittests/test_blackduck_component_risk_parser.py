from django.test import TestCase
from dojo.tools.blackduck_component_risk.parser import BlackduckHubParser
from dojo.models import Test
from pathlib import Path


class TestBlackduckHubCRParser(TestCase):
    def test_blackduck_enhanced_zip_upload(self):
        testfile = Path("dojo/unittests/scans/blackduck_component_risk/"
                        "blackduck_hub_component_risk.zip")
        parser = BlackduckHubParser(testfile, Test())
        self.assertEqual(12, len(parser.items))
