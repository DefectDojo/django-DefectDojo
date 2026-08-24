from dojo.models import Test
from dojo.tools.modelscan.parser import ModelScanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestModelScanParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("modelscan") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = ModelScanParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("modelscan") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = ModelScanParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Unsafe operator 'system' from module 'posix'", finding.title)
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("posix.system", finding.vuln_id_from_tool)
            self.assertEqual("model_a.pkl", finding.file_path)
            self.assertEqual("model_a.pkl", finding.component_name)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertIn("Use of unsafe operator", finding.description)
            self.assertIn("modelscan.scanners.PickleUnsafeOpScan", finding.description)
            self.assertIn("safetensors", finding.mitigation)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("modelscan") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = ModelScanParser().get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            self.assertEqual(
                {"Critical", "High"},
                {finding.severity for finding in findings},
            )

            with self.subTest("HIGH maps to High and keeps its own module"):
                high = next(f for f in findings if f.severity == "High")
                self.assertEqual("Unsafe operator 'open' from module 'webbrowser'", high.title)
                self.assertEqual("webbrowser.open", high.vuln_id_from_tool)
                self.assertEqual("model_d.pkl", high.file_path)

            with self.subTest("the report's scanner version reaches the description"):
                for finding in findings:
                    self.assertIn("**ModelScan version:**", finding.description)
