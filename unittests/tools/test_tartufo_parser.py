from dojo.models import Test
from dojo.tools.tartufo.parser import TartufoParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTartufoParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("tartufo") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = TartufoParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("tartufo") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = TartufoParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("AWS API Key in config.py", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("config.py", finding.file_path)
            self.assertEqual("Regular Expression Match", finding.vuln_id_from_tool)
            self.assertTrue(finding.unique_id_from_tool)
            self.assertIn("**Branch:** main", finding.description)
            self.assertIn("**Commit:**", finding.description)
            self.assertIn("Rotate the exposed credential", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_a_secret_in_history_records_its_commit(self):
        with (get_unit_tests_scans_path("tartufo") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = TartufoParser().get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            self.assertEqual({"High"}, {f.severity for f in findings})

            with self.subTest("each match keeps its own signature"):
                self.assertEqual(2, len({f.unique_id_from_tool for f in findings}))

            with self.subTest("the entropy match lands on its own file"):
                entropy = next(f for f in findings if f.vuln_id_from_tool == "High Entropy")
                self.assertEqual("settings/prod.py", entropy.file_path)
                self.assertIn("**Commit:** deadbeefcafebabe", entropy.description)
