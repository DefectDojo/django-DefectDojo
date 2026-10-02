import io
import json

from dojo.models import Finding, Test
from dojo.tools.conftest.parser import ConftestParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestConftestParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("conftest") / filename).open(encoding="utf-8") as file:
            return list(ConftestParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("conftest") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = ConftestParser()
        self.assertEqual(["Conftest Scan"], parser.get_scan_types())
        self.assertEqual("Conftest Scan", parser.get_label_for_scan_types("Conftest Scan"))
        self.assertIn("conftest test", parser.get_description_for_scan_types("Conftest Scan"))

    def test_no_vuln(self):
        """
        A clean run OMITS the failures and warnings keys rather than emitting empty arrays.

        That is worth pinning: indexing them directly would fail on a clean report, which is the
        case a user is most likely to hit first. Only `successes`, a count, is present.
        """
        report = self.report("conftest_no_vuln.json")
        self.assertEqual(["filename", "namespace", "successes"], sorted(report[0]))
        self.assertEqual(4, report[0]["successes"])
        self.assertEqual(0, len(self.parse("conftest_no_vuln.json")))

    def test_successes_is_a_count_not_a_list(self):
        """Conftest reports how many rules passed, not which - so passes cannot become findings."""
        report = self.report("conftest_many_vuln.json")
        self.assertIsInstance(report[0]["successes"], int)

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("conftest_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `conftest test --output json` run."""
        findings = self.parse("conftest_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Container server must set a memory limit", finding.title)
        self.assertEqual("data.main.deny", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("single.yaml", finding.file_path)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Result:** deny", finding.description)
        self.assertIn("**Policy namespace:** main", finding.description)
        self.assertIn("**Query:** data.main.deny", finding.description)

    def test_no_line_number(self):
        finding = self.parse("conftest_one_vuln.json")[0]
        self.assertIsNone(getattr(finding, "line", None))

    def test_many_vuln(self):
        findings = self.parse("conftest_many_vuln.json")
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertEqual("many.yaml", finding.file_path)
            self.assertIn(finding.severity, Finding.SEVERITIES)

    def test_deny_and_warn_are_separate_severities(self):
        """
        Conftest's only severity signal is which array a result landed in.

        A Rego `deny` rule goes to failures and a `warn` rule to warnings, so the two map to
        different severities and the description records which one it was.
        """
        report = self.report("conftest_many_vuln.json")
        self.assertEqual(3, len(report[0]["failures"]))
        self.assertEqual(1, len(report[0]["warnings"]))

        findings = self.parse("conftest_many_vuln.json")
        high = [f for f in findings if f.severity == "High"]
        medium = [f for f in findings if f.severity == "Medium"]
        self.assertEqual(3, len(high))
        self.assertEqual(1, len(medium))

        self.assertIn("app.kubernetes.io/name label", medium[0].title)
        self.assertIn("**Result:** warn", medium[0].description)
        self.assertEqual("data.main.warn", medium[0].vuln_id_from_tool)

    def test_many_vuln_messages(self):
        findings = self.parse("conftest_many_vuln.json")
        self.assertEqual(
            [
                "Container server must not use the :latest tag",
                "Container server must set a memory limit",
                "Deployment generic-app must set securityContext.runAsNonRoot",
                "Deployment generic-app should carry an app.kubernetes.io/name label",
            ],
            sorted(finding.title for finding in findings),
        )

    def test_exceptions_and_skipped_are_not_findings(self):
        """
        An exception is a rule the policy author explicitly allowed; a skipped policy never ran.

        Neither is a finding, so both arrays are ignored even though conftest reports them.
        """
        report = io.StringIO(json.dumps([{
            "filename": "t.yaml",
            "namespace": "main",
            "successes": 1,
            "exceptions": [{"msg": "allowed by exception", "metadata": {"query": "data.main.exception"}}],
            "skipped": [{"msg": "policy skipped", "metadata": {"query": "data.main.skip"}}],
        }]))
        self.assertEqual([], list(ConftestParser().get_findings(report, Test())))

    def test_result_without_metadata(self):
        """A policy need not attach metadata, and the finding degrades rather than crashing."""
        report = io.StringIO(json.dumps([{
            "filename": "t.yaml", "namespace": "main", "successes": 0,
            "failures": [{"msg": "bare message"}],
        }]))
        finding = list(ConftestParser().get_findings(report, Test()))[0]
        self.assertEqual("bare message", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertNotIn("**Query:**", finding.description)

    def test_extra_metadata_is_kept(self):
        """A policy is free to attach anything else to metadata, and it should not be dropped."""
        report = io.StringIO(json.dumps([{
            "filename": "t.yaml", "namespace": "main", "successes": 0,
            "failures": [{"msg": "m", "metadata": {"query": "data.main.deny", "severity": "critical",
                                                    "control": "CIS-5.2.1"}}],
        }]))
        finding = list(ConftestParser().get_findings(report, Test()))[0]
        self.assertIn("**control:** CIS-5.2.1", finding.description)
        self.assertIn("**severity:** critical", finding.description)

    def test_several_files_in_one_report(self):
        report = io.StringIO(json.dumps([
            {"filename": "a.yaml", "namespace": "main", "successes": 0,
             "failures": [{"msg": "one"}]},
            {"filename": "b.yaml", "namespace": "main", "successes": 0,
             "warnings": [{"msg": "two"}]},
        ]))
        findings = list(ConftestParser().get_findings(report, Test()))
        self.assertEqual(2, len(findings))
        self.assertEqual(["a.yaml", "b.yaml"], sorted(f.file_path for f in findings))

    def test_empty_report(self):
        self.assertEqual([], list(ConftestParser().get_findings(io.StringIO("[]"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(ConftestParser().get_findings(io.StringIO('{"results": []}'), Test()))
        with self.assertRaises(TypeError):
            list(ConftestParser().get_findings(io.StringIO("[2]"), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("conftest_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("single.yaml", locations[0].data["file_path"])
