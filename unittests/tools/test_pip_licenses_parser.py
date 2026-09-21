from dojo.models import Test
from dojo.tools.pip_licenses.parser import PipLicensesParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPipLicensesParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("pip_licenses") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = PipLicensesParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """A package with a declared licence is inventory, so it is informational."""
        with (get_unit_tests_scans_path("pip_licenses") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = PipLicensesParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Authlib 1.7.2: BSD License", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("Authlib", finding.component_name)
            self.assertEqual("1.7.2", finding.component_version)
            self.assertEqual("BSD License", finding.vuln_id_from_tool)
            self.assertIn("**License:** BSD License", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_undetermined_licence_outranks_inventory(self):
        with (get_unit_tests_scans_path("pip_licenses") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = PipLicensesParser().get_findings(testfile, Test())
            self.assertEqual(7, len(findings))

            with self.subTest("a package with no determinable licence is raised to Low"):
                low = [f for f in findings if f.severity == "Low"]
                self.assertEqual(1, len(low))
                self.assertEqual("ida-settings", low[0].component_name)
                self.assertIn("could not determine a licence", low[0].description)

            with self.subTest("everything else stays informational"):
                self.assertEqual(6, len([f for f in findings if f.severity == "Info"]))

            with self.subTest("every package is inventoried with a version"):
                for finding in findings:
                    self.assertTrue(finding.component_name)
                    self.assertTrue(finding.component_version)
