import io
import json

from dojo.models import Finding, Test
from dojo.tools.hackerone.parser import HackerOneParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHackerOneParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("hackerone") / filename).open(encoding="utf-8") as file:
            return list(HackerOneParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal ScanTypeName in the HackerOne connector verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = HackerOneParser()
        self.assertEqual(["HackerOne - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "HackerOne - Connectors Import",
            parser.get_label_for_scan_types("HackerOne - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("hackerone_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("hackerone_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring toFinding in the connector's converter."""
        findings = self.parse("hackerone_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Stored XSS in the profile page", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("1000001", finding.unique_id_from_tool)
        # The converter puts the report id in BOTH id fields.
        self.assertEqual("1000001", finding.vuln_id_from_tool)
        self.assertEqual(79, finding.cwe)
        self.assertEqual(7.6, finding.cvssv3_score)
        self.assertEqual("https://hackerone.com/reports/1000001", finding.url)

        self.assertIn("stored cross-site scripting issue", finding.description)
        self.assertIn("**Weakness:** Cross-site Scripting (XSS) - Stored", finding.description)
        self.assertIn("**Reported by:** researcher-one", finding.description)
        self.assertIn("**Report:** https://hackerone.com/reports/1000001", finding.description)

    def test_severity_weakness_and_reporter_are_json_api_relationships(self):
        """
        These three are relationships on a HackerOne report, not attributes.

        Reading them off the top level - or off "attributes" - would leave every finding at Info with
        no CWE and no reporter, because the API never puts them there.
        """
        raw = json.loads((get_unit_tests_scans_path("hackerone")
                          / "hackerone_one_vuln.json").read_text(encoding="utf-8"))
        report = raw["data"][0]
        self.assertNotIn("severity", report["attributes"])
        self.assertNotIn("severity", report)
        self.assertIn("severity", report["relationships"])

        finding = self.parse("hackerone_one_vuln.json")[0]
        self.assertEqual("High", finding.severity)
        self.assertEqual(79, finding.cwe)

    def test_an_already_flattened_export_is_also_accepted(self):
        """
        Someone exporting through a script may flatten the envelope.

        The connector reads JSON:API, but accepting the flattened shape costs nothing and avoids a
        confusing empty import.
        """
        report = io.StringIO(json.dumps({"data": [{
            "id": "42",
            "title": "A flattened report",
            "vulnerability_information": "Details.",
            "severity": {"rating": "critical", "score": 9.1},
            "weakness": {"external_id": "cwe-89", "name": "SQL Injection"},
            "reporter": {"username": "researcher"},
        }]}))
        finding = list(HackerOneParser().get_findings(report, Test()))[0]
        self.assertEqual("A flattened report", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertEqual(89, finding.cwe)
        self.assertEqual(9.1, finding.cvssv3_score)
        self.assertIn("**Reported by:** researcher", finding.description)

    def test_the_severity_ladder_is_the_connectors(self):
        findings = self.by_uid("hackerone_many_vuln.json")
        self.assertEqual("High", findings["1000001"].severity)
        self.assertEqual("Medium", findings["1000002"].severity)
        # HackerOne's "none" rating is not a DefectDojo severity, so it falls through to Info.
        self.assertEqual("Info", findings["1000003"].severity)
        # The comparison is case-insensitive.
        self.assertEqual("Critical", findings["1000004"].severity)

    def test_a_report_with_no_severity_score_gets_none(self):
        """The converter only sets a score when HackerOne attached one above zero."""
        finding = self.by_uid("hackerone_many_vuln.json")["1000003"]
        self.assertIsNone(finding.cvssv3_score)

    def test_a_weakness_id_that_is_not_a_cwe_leaves_the_cwe_at_zero(self):
        """
        HackerOne weakness ids are lower-cased "cwe-<n>", but not every weakness maps to a CWE.

        Finding.cwe is an IntegerField with default 0, so this reads as 0 rather than None.
        """
        finding = self.by_uid("hackerone_many_vuln.json")["1000004"]
        self.assertEqual(0, finding.cwe)

    def test_the_cwe_parse_directly(self):
        parser = HackerOneParser()
        self.assertEqual(79, parser.cwe("cwe-79"))
        self.assertEqual(79, parser.cwe("CWE-79"))
        self.assertEqual(307, parser.cwe("cwe-307"))
        self.assertEqual(0, parser.cwe("capec-63"))
        self.assertEqual(0, parser.cwe("cwe-none"))
        self.assertEqual(0, parser.cwe(""))
        self.assertEqual(0, parser.cwe(None))

    def test_a_report_with_no_relationships_still_imports(self):
        """A report can arrive with no severity, weakness or reporter linked at all."""
        finding = self.by_uid("hackerone_many_vuln.json")["1000005"]
        self.assertEqual("Report with no relationships at all", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertEqual(0, finding.cwe)
        self.assertIsNone(finding.cvssv3_score)
        self.assertNotIn("**Weakness:**", finding.description)
        self.assertNotIn("**Reported by:**", finding.description)

    def test_the_report_link_is_always_appended(self):
        """
        Every finding gets the link, even one with no prose at all.

        A bug-bounty finding is not actionable without a way back to the report and its comments.
        """
        finding = self.by_uid("hackerone_many_vuln.json")["1000003"]
        self.assertEqual(
            "**Report:** https://hackerone.com/reports/1000003", finding.description,
        )
        self.assertEqual("https://hackerone.com/reports/1000003", finding.url)

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([{
            "id": "7", "attributes": {"title": "A report"},
            "relationships": {"severity": {"data": {"attributes": {"rating": "low"}}}},
        }]))
        findings = list(HackerOneParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("Low", findings[0].severity)

    def test_a_repeated_report_id_collapses(self):
        report = {"id": "same", "attributes": {"title": "A report"}}
        payload = io.StringIO(json.dumps({"data": [report, report]}))
        self.assertEqual(1, len(list(HackerOneParser().get_findings(payload, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(HackerOneParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("data", str(raised.exception))
