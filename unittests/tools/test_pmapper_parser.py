from dojo.models import Test
from dojo.tools.pmapper.parser import PMapperParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPMapperParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("pmapper") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = PMapperParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("pmapper") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = PMapperParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(
                "IAM Role Available to Compute Service That Can Escalate Privileges",
                finding.vuln_id_from_tool,
            )
            self.assertEqual("000000000000", finding.component_name)
            self.assertIn("000000000000", finding.title)

            with self.subTest("PMapper's own impact and recommendation are kept in place"):
                self.assertIn("administrative access", finding.impact)
                self.assertIn("Restrict iam:PassRole", finding.mitigation)

            with self.subTest("the principals involved are described"):
                self.assertIn("sample-instance-role", finding.description)
                self.assertIn("**AWS account:** 000000000000", finding.description)
                self.assertIn("**Analysed at:**", finding.description)

    def test_parse_many_findings(self):
        """PMapper grades its own findings, so the three do not land on one severity."""
        with (get_unit_tests_scans_path("pmapper") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = PMapperParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            self.assertEqual(
                ["High", "Medium", "Low"],
                [f.severity for f in findings],
            )

            with self.subTest("every finding carries a recommendation to act on"):
                for finding in findings:
                    self.assertTrue(finding.mitigation)
                    self.assertTrue(finding.impact)
                    self.assertEqual("000000000000", finding.component_name)

    def test_an_unknown_severity_does_not_become_critical_by_accident(self):
        parser = PMapperParser()
        finding = parser._to_finding(
            {"title": "Something", "severity": "unheard-of", "impact": "", "description": "", "recommendation": ""},
            "000000000000", "sample", "2026-08-10T09:00:00", Test(),
        )
        self.assertEqual("Medium", finding.severity)
