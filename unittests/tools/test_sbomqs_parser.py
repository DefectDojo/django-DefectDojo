from dojo.models import Test
from dojo.tools.sbomqs.parser import SbomqsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSbomqsParser(DojoTestCase):

    def test_parse_no_findings(self):
        """A feature scoring its maximum is not a gap."""
        with (get_unit_tests_scans_path("sbomqs") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = SbomqsParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("sbomqs") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = SbomqsParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("NTIA-minimum-elements: comp_with_supplier", finding.title)
            self.assertEqual("comp_with_supplier", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("sbom.json", finding.file_path)
            self.assertIn("0/1 have supplier names", finding.description)
            self.assertIn("**Score:** 0 of 10", finding.description)
            self.assertIn("**Spec:** cyclonedx 1.4", finding.description)
            self.assertIn("**Document average score:** 3.39", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("sbomqs") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = SbomqsParser().get_findings(testfile, Test())
            self.assertEqual(8, len(findings))

            with self.subTest("a feature scoring zero is the most serious gap"):
                self.assertEqual({"Medium"}, {f.severity for f in findings})

            with self.subTest("findings span the guidance categories sbomqs scores against"):
                categories = {f.title.split(":")[0] for f in findings}
                self.assertIn("NTIA-minimum-elements", categories)

            with self.subTest("every finding names the SBOM it came from"):
                for finding in findings:
                    self.assertEqual("sbom.json", finding.component_name)
                    self.assertIn("Regenerate the SBOM", finding.mitigation)

    def test_severity_scales_with_the_size_of_the_gap(self):
        parser = SbomqsParser()
        self.assertEqual("Medium", parser._severity(0, 10))
        self.assertEqual("Low", parser._severity(4, 10))
        self.assertEqual("Info", parser._severity(7, 10))
        self.assertEqual("Info", parser._severity(0, 0))
