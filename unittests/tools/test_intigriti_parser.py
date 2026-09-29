import io
import json

from dojo.models import Finding, Test
from dojo.tools.intigriti.parser import IntigritiParser, inert_text
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestIntigritiParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("intigriti") / filename).open(encoding="utf-8") as file:
            return list(IntigritiParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Intigriti connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = IntigritiParser()
        self.assertEqual(["Intigriti - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Intigriti - Connectors Import",
            parser.get_label_for_scan_types("Intigriti - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("intigriti_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("intigriti_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("intigriti_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Stored XSS in the comment field", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("GENERIC-0001", finding.unique_id_from_tool)
        self.assertEqual("GENERIC-0001", finding.vuln_id_from_tool)
        self.assertEqual(79, finding.cwe)
        self.assertEqual(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", finding.cvssv3,
        )
        self.assertEqual("https://app.example.com/submissions/GENERIC-0001", finding.url)
        self.assertEqual(
            "Intigriti submission: https://app.example.com/submissions/GENERIC-0001",
            finding.references,
        )
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)

    def test_intigritis_top_tier_is_exceptional_not_critical(self):
        """
        Intigriti grades its most severe submissions "Exceptional".

        Mapping only "critical" would silently drop every top-tier submission to Info.
        """
        parser = IntigritiParser()
        self.assertEqual("Critical", parser.build_finding(
            {"code": "X", "severity": {"value": "Exceptional"}}, Test()).severity)
        self.assertEqual("Critical", parser.build_finding(
            {"code": "X", "severity": {"value": "critical"}}, Test()).severity)
        for value, expected in [("High", "High"), ("Medium", "Medium"), ("Low", "Low"),
                                ("not-a-severity", "Info"), ("", "Info")]:
            self.assertEqual(expected, parser.build_finding(
                {"code": "X", "severity": {"value": value}}, Test()).severity, value)

    def test_the_status_and_close_reason_become_the_defectdojo_state(self):
        """
        For a closed submission the CLOSE REASON is what distinguishes a fix from a rejection.

        Treating every closed submission the same way would mark rejected and duplicate submissions
        as mitigated, which reads as work completed.
        """
        findings = self.by_uid("intigriti_many_vuln.json")

        accepted = findings["GENERIC-0001"]
        self.assertTrue(accepted.active)
        self.assertTrue(accepted.verified)

        solved = findings["GENERIC-0002"]
        self.assertFalse(solved.active)
        self.assertTrue(solved.is_mitigated)
        self.assertTrue(solved.verified)

        risk = findings["GENERIC-0003"]
        self.assertFalse(risk.active)
        self.assertTrue(risk.risk_accepted)
        self.assertFalse(risk.is_mitigated)

        duplicate = findings["GENERIC-0004"]
        self.assertFalse(duplicate.active)
        self.assertTrue(duplicate.duplicate)

        out_of_scope = findings["GENERIC-0005"]
        self.assertFalse(out_of_scope.active)
        self.assertTrue(out_of_scope.out_of_scope)

        rejected = findings["GENERIC-0006"]
        self.assertFalse(rejected.active)
        self.assertTrue(rejected.false_p)

    def test_intigritis_terse_rejection_reason_is_a_false_positive(self):
        """The close reason "No" is Intigriti's shortest rejection, and it must not read as fixed."""
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0007"]
        self.assertFalse(finding.active)
        self.assertTrue(finding.false_p)
        self.assertFalse(finding.is_mitigated)

    def test_an_archived_submission_is_treated_as_closed(self):
        """Both "closed" and "archived" route through the close-reason branch."""
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0005"]
        self.assertFalse(finding.active)

    def test_an_open_submission_is_active_but_not_verified(self):
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0008"]
        self.assertTrue(finding.active)
        self.assertFalse(finding.verified)

    def test_a_closed_submission_with_an_unknown_reason_is_treated_as_fixed(self):
        parser = IntigritiParser()
        finding = Finding()
        parser.apply_state(finding, "Closed", "some new reason")
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertTrue(finding.verified)

    def test_researcher_html_is_flattened_not_rendered(self):
        """
        Intigriti submissions are written by external researchers.

        Their prose is flattened and escaped, so nothing in a submission can be injected into a
        rendered finding.
        """
        finding = self.parse("intigriti_one_vuln.json")[0]
        self.assertIn("**Proof of concept:**", finding.description)
        self.assertIn("Submit", finding.description)
        # The script content is dropped and no raw markup survives anywhere.
        self.assertNotIn("alert(1)", finding.description)
        self.assertNotIn("<script", finding.description)
        self.assertNotIn("<b>", finding.description)
        self.assertNotIn("<p>", finding.impact)
        self.assertNotIn("<p>", finding.mitigation)

    def test_the_inert_text_helper_matches_gos_entities(self):
        self.assertEqual("plain", inert_text("plain"))
        self.assertEqual("kept", inert_text("<script>dropped()</script>kept"))
        self.assertEqual("a\n\nb", inert_text("<p>a</p><p>b</p>"))
        self.assertEqual("&#39;q&#39;", inert_text("'q'"))
        self.assertEqual("&#34;q&#34;", inert_text('"q"'))
        self.assertEqual("", inert_text(""))

    def test_the_impact_and_solution_become_impact_and_mitigation(self):
        finding = self.parse("intigriti_one_vuln.json")[0]
        self.assertEqual(
            "An attacker can run script in another user&#39;s session.", finding.impact,
        )
        self.assertEqual("Encode user input before rendering.", finding.mitigation)

    def test_the_description_carries_the_type_asset_and_question_answers(self):
        finding = self.parse("intigriti_one_vuln.json")[0]
        self.assertIn("**Type:** Cross-site Scripting (Injection)", finding.description)
        self.assertIn("**Asset:** app.example.com", finding.description)
        self.assertIn("**Which browsers did you test?**", finding.description)
        self.assertIn("Latest Chrome and Firefox.", finding.description)
        self.assertIn("**Submission:** GENERIC-0001", finding.description)

    def test_an_empty_question_and_answer_pair_is_skipped(self):
        """The fixture carries one, and it must not produce a heading with nothing under it."""
        finding = self.parse("intigriti_one_vuln.json")[0]
        self.assertNotIn("****\n", finding.description)

    def test_the_asset_falls_back_to_the_vulnerable_component(self):
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0009"]
        self.assertIn("**Asset:** api.example.com/v1/users", finding.description)

    def test_a_report_type_with_only_a_category_still_renders(self):
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0009"]
        self.assertIn("**Type:** Access Control", finding.description)

    def test_a_detail_carried_on_the_entry_itself_is_recognised(self):
        """
        The connector fetches the detail separately, so an export may nest it or merge it.

        A merged export is recognised by the presence of "report"; missing that would lose the CWE,
        impact, solution and the whole description body.
        """
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0009"]
        self.assertIn("**Asset:**", finding.description)

    def test_a_cwe_that_is_not_prefixed_leaves_the_cwe_at_zero(self):
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0009"]
        self.assertEqual(0, finding.cwe)

    def test_the_cwe_parse_directly(self):
        parser = IntigritiParser()
        self.assertEqual(79, parser.cwe("cwe-79"))
        self.assertEqual(79, parser.cwe("CWE-79"))
        self.assertEqual(0, parser.cwe("not-a-cwe"))
        self.assertEqual(0, parser.cwe("79"))
        self.assertEqual(0, parser.cwe(""))

    def test_a_submission_with_no_portal_link_has_no_url_or_references(self):
        finding = self.by_uid("intigriti_many_vuln.json")["GENERIC-0003"]
        self.assertIsNone(finding.url)
        self.assertIsNone(finding.references)

    def test_the_overview_wins_when_both_objects_carry_a_field(self):
        """
        The converter prefers the overview for any field both carry.

        The fixture's detail has an empty severity vector while the overview has one, so a
        detail-first reading would lose it.
        """
        finding = self.parse("intigriti_one_vuln.json")[0]
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N", finding.cvssv3)

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "code": "X-1", "title": "A submission", "severity": {"value": "High"},
            "state": {"status": {"value": "Open"}},
        }]))
        findings = list(IntigritiParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_a_repeated_submission_code_collapses(self):
        row = {"code": "same", "title": "A submission", "severity": {"value": "Low"}}
        report = io.StringIO(json.dumps({"records": [row, row]}))
        self.assertEqual(1, len(list(IntigritiParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(IntigritiParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("records", str(raised.exception))
