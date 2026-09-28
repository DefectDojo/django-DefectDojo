import io
import json

from dojo.models import Test
from dojo.tools.fickling.parser import FicklingParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFicklingParser(DojoTestCase):

    def test_parse_no_findings(self):
        """A pickle Fickling judges LIKELY_SAFE has nothing to report."""
        with (get_unit_tests_scans_path("fickling") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = FicklingParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("fickling") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = FicklingParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("UnsafeImports: LIKELY_OVERTLY_MALICIOUS", finding.title)
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("UnsafeImports", finding.vuln_id_from_tool)
            self.assertIn("from posix import system", finding.description)
            self.assertIn("**Verdict:** LIKELY_OVERTLY_MALICIOUS", finding.description)
            self.assertIn("Do not unpickle this file", finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        """Each observation behind the verdict becomes its own Finding."""
        with (get_unit_tests_scans_path("fickling") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = FicklingParser().get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            self.assertEqual(
                {"UnsafeImports", "UnusedVariables"},
                {f.vuln_id_from_tool for f in findings},
            )
            self.assertEqual({"Critical"}, {f.severity for f in findings})

    def test_verdict_without_itemised_results_is_still_reported(self):
        """Fickling can return a verdict with an empty detailed_results block."""
        report = {"severity": "SUSPICIOUS", "analysis": "something odd", "detailed_results": {}}
        findings = FicklingParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("Pickle flagged as SUSPICIOUS", findings[0].title)
        self.assertEqual("Medium", findings[0].severity)

    def test_verdict_scale(self):
        parser = FicklingParser()
        self.assertEqual("Critical", parser.SEVERITY["OVERTLY_MALICIOUS"])
        self.assertEqual("Critical", parser.SEVERITY["LIKELY_OVERTLY_MALICIOUS"])
        self.assertEqual("High", parser.SEVERITY["LIKELY_UNSAFE"])
        self.assertEqual("Medium", parser.SEVERITY["SUSPICIOUS"])
        self.assertEqual("Info", parser.SEVERITY["LIKELY_SAFE"])
