from dojo.models import Test
from dojo.tools.regula.parser import RegulaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRegulaParser(DojoTestCase):

    def test_parse_no_findings(self):
        """Regula reports passing rules alongside failures; passes are not findings."""
        with (get_unit_tests_scans_path("regula") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = RegulaParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("regula") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = RegulaParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("FG_R00253", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertEqual("aws_instance.example", finding.component_name)
            self.assertEqual("terraform/main.tf", finding.file_path)
            self.assertEqual(6, finding.line)
            self.assertIn("EC2 instances should use IAM roles", finding.title)
            self.assertIn("**Provider:** aws", finding.description)
            self.assertIn("**Input type:** tf", finding.description)
            self.assertEqual("https://docs.fugue.co/FG_R00253.html", finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("regula") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = RegulaParser().get_findings(testfile, Test())
            self.assertEqual(9, len(findings))

            with self.subTest("regula's own severity scale is preserved"):
                self.assertEqual(3, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(4, len([f for f in findings if f.severity == "Medium"]))
                self.assertEqual(2, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("every failure names the resource it applies to"):
                for finding in findings:
                    self.assertTrue(finding.component_name)
                    self.assertEqual("terraform/main.tf", finding.file_path)
                    self.assertTrue(finding.vuln_id_from_tool.startswith("FG_R"))

    def test_line_comes_from_the_first_source_location(self):
        parser = RegulaParser()
        self.assertEqual(12, parser._line({"source_location": [{"path": "main.tf", "line": 12}]}))
        self.assertIsNone(parser._line({"source_location": []}))
        self.assertIsNone(parser._line({}))
