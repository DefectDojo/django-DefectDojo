from dojo.models import Test
from dojo.tools.syft.parser import SyftParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSyftParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("syft") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = SyftParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("syft") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = SyftParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("certifi:2026.7.22", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("certifi", finding.component_name)
            self.assertEqual("2026.7.22", finding.component_version)
            self.assertEqual("pkg:pypi/certifi@2026.7.22", finding.vuln_id_from_tool)
            self.assertEqual("94f96c9665535457", finding.unique_id_from_tool)
            self.assertIn("**Language:** python", finding.description)
            self.assertIn("**Source:** app/", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_an_sbom_records_presence_not_defects(self):
        with (get_unit_tests_scans_path("syft") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = SyftParser().get_findings(testfile, Test())
            self.assertEqual(14, len(findings))
            self.assertEqual({"Info"}, {f.severity for f in findings})

            with self.subTest("every catalogued package keeps its own identity"):
                self.assertEqual(14, len({f.unique_id_from_tool for f in findings}))
                for finding in findings:
                    self.assertTrue(finding.component_name)

            with self.subTest("packages with no declared licence say so explicitly"):
                self.assertIn("**Licenses:** none declared", findings[0].description)

    def test_licenses_are_read_from_both_schema_shapes(self):
        parser = SyftParser()
        self.assertEqual(["MIT"], parser._licenses({"licenses": [{"value": "MIT"}]}))
        self.assertEqual(["Apache-2.0"], parser._licenses({"licenses": [{"spdxExpression": "Apache-2.0"}]}))
        self.assertEqual(["BSD"], parser._licenses({"licenses": ["BSD"]}))
        self.assertEqual([], parser._licenses({}))
