from dojo.models import Finding, Test
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

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("CVE-0123-25511 Affects linux-image-6.8.0-60-generic (Version: 6.8.0-60.63)", finding.title)
                self.assertEqual("Critical", finding.severity)
                self.assertEqual("linux-image-6.8.0-60-generic", finding.component_name)
                self.assertEqual("6.8.0-60.63", finding.component_version)
                self.assertEqual(["CVE-0123-25511"], finding.unsaved_vulnerability_ids)
                self.assertEqual(9.1, finding.cvssv3_score)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                self.assertEqual("myhost2", finding.unsaved_endpoints[0].host)

            with self.subTest(i=10):
                finding = findings[10]
                self.assertEqual("CVE-2023-28322 Affects libcurl-devel (Version: 7.29.0-59.el7_9.2)", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("libcurl-devel", finding.component_name)
                self.assertEqual("7.29.0-59.el7_9.2", finding.component_version)
                self.assertEqual(["CVE-2023-28322"], finding.unsaved_vulnerability_ids)
                self.assertEqual(3.7, finding.cvssv3_score)
                self.assertEqual("asdasdasd", finding.unsaved_endpoints[0].host)

            for i, finding in enumerate(findings):
                with self.subTest(finding_index=i):
                    self.assertIsNotNone(finding.title)
                    self.assertIn(finding.severity, Finding.SEVERITIES)
                    self.assertIsNotNone(finding.component_name)
                    self.assertIsNotNone(finding.component_version)
                    self.assertTrue(len(finding.unsaved_vulnerability_ids) > 0)
                    self.assertTrue(len(finding.unsaved_endpoints) > 0)
                    self.assertEqual(False, finding.static_finding)
                    self.assertEqual(True, finding.dynamic_finding)
