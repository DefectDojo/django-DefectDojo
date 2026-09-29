from dojo.models import Test
from dojo.tools.licensecheck.parser import LicensecheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestLicensecheckParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("licensecheck") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = LicensecheckParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """The incompatible package is the real finding; the compatible ones are inventory."""
        with (get_unit_tests_scans_path("licensecheck") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = LicensecheckParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            incompatible = [f for f in findings if f.severity == "High"]
            self.assertEqual(1, len(incompatible))
            finding = incompatible[0]
            self.assertEqual("certifi", finding.component_name)
            self.assertIn("incompatible with project", finding.title)
            self.assertIn("**Compatible with project license:** False", finding.description)
            self.assertIn("Replace this dependency", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("compatible packages are informational inventory"):
                self.assertEqual(2, len([f for f in findings if f.severity == "Info"]))

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("licensecheck") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = LicensecheckParser().get_findings(testfile, Test())
            self.assertEqual(11, len(findings))

            with self.subTest("exactly the incompatible dependency is raised"):
                self.assertEqual(1, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(10, len([f for f in findings if f.severity == "Info"]))

            with self.subTest("every package is inventoried with its licence"):
                for finding in findings:
                    self.assertTrue(finding.component_name)
                    self.assertTrue(finding.vuln_id_from_tool)
