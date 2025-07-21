from dojo.models import Test
from dojo.tools.wazuh_indexer.parser import WazuhIndexerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWazuhIndexerParser(DojoTestCase):

    def test_parse_v4_8_no_findings(self):
        with (get_unit_tests_scans_path("wazuh_indexer") / "v4-8_no_findings.json").open(encoding="utf-8") as testfile:
            parser = WazuhIndexerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_v4_8_one_finding(self):
        with (get_unit_tests_scans_path("wazuh_indexer") / "v4-8_one_finding.json").open(encoding="utf-8") as testfile:
            parser = WazuhIndexerParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2024-27282 Affects ruby2.5 (Version: 2.5.1-1ubuntu1.16)", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("ruby2.5", finding.component_name)
            self.assertEqual("2.5.1-1ubuntu1.16", finding.component_version)

    def test_parse_v4_8_many_findings(self):
        with (get_unit_tests_scans_path("wazuh_indexer") / "v4-8_many_findings.json").open(encoding="utf-8") as testfile:
            parser = WazuhIndexerParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(15, len(findings))

            finding = findings[0]
            self.assertEqual("CVE-0123-25511 Affects linux-image-6.8.0-60-generic (Version: 6.8.0-60.63)", finding.title)
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("linux-image-6.8.0-60-generic", finding.component_name)
            self.assertEqual("6.8.0-60.63", finding.component_version)
            self.assertEqual(9.1, finding.cvssv3_score)
            self.assertEqual("myhost0", finding.unsaved_endpoints[0].host)
