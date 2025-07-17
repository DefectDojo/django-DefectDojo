from dojo.models import Test
from dojo.tools.wazuh_indexer.parser import WazuhIndexerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWazuhIndexerParser(DojoTestCase):

    def test_parse_v4_8_many_findings(self):
        with (get_unit_tests_scans_path("wazuh_indexer") / "v4-8_many_findings.json").open(encoding="utf-8") as testfile:
            parser = WazuhIndexerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(10, len(findings))
            self.assertEqual("CVE-0123-25511 Affects linux-image-6.8.0-60-generic (Version: 6.8.0-60.63)", findings[0].title)
            self.assertEqual("Critical", findings[0].severity)