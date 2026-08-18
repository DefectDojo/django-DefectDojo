from dojo.models import Test
from dojo.tools.gixy.parser import GixyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGixyParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("gixy") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = GixyParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("gixy") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = GixyParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("version_disclosure", finding.vuln_id_from_tool)
            self.assertEqual("nginx/nginx.conf", finding.file_path)
            self.assertEqual(2, finding.line)
            self.assertTrue(finding.title.startswith("version_disclosure: "))
            self.assertIn("**Plugin:** version_disclosure", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("gixy") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = GixyParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("Gixy's own severity is used"):
                self.assertEqual(2, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(1, len([f for f in findings if f.severity == "Medium"]))

            with self.subTest("the http-splitting plugin is present"):
                self.assertIn("http_splitting", {f.vuln_id_from_tool for f in findings})

            with self.subTest("every finding is anchored in the config"):
                for finding in findings:
                    self.assertEqual("nginx/nginx.conf", finding.file_path)
                    self.assertIsNotNone(finding.line)
