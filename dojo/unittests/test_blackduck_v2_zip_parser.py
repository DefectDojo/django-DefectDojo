from django.test import TestCase
from dojo.tools.blackduck_v2.parser import BlackduckHubParser
from dojo.models import Test
from pathlib import Path


class TestBlackduckHubV2Parser(TestCase):
    def test_blackduck_enhanced_zip_upload(self):
        testfile = Path("dojo/unittests/scans/blackduck_v2/blackduck_hub_v2.zip")
        parser = BlackduckHubParser(testfile, Test())
        self.assertEqual(12, len(parser.items))
