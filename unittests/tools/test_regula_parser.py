import io
import json

from dojo.models import Finding, Test
from dojo.tools.regula.parser import RegulaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRegulaParser(DojoTestCase):
    def scan(self, filename):
        return get_unit_tests_scans_path("regula") / filename

    def parse(self, filename):
        with self.scan(filename).open(encoding="utf-8") as file:
            return list(RegulaParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_metadata(self):
        parser = RegulaParser()
        self.assertEqual(["Regula Scan"], parser.get_scan_types())
        self.assertEqual("Regula Scan", parser.get_label_for_scan_types("Regula Scan"))
        self.assertIn("failed rules", parser.get_description_for_scan_types("Regula Scan"))

    def test_no_vuln(self):
        """A report where every rule passed yields no findings, not 40 Info items."""
        self.assertEqual(0, len(self.parse("regula_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("regula_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        findings = self.parse("regula_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "CloudTrail trails should have CloudWatch log integration enabled", finding.title,
        )
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("aws_cloudtrail", finding.component_name)
        self.assertEqual("infra/main.tf", finding.file_path)
        self.assertEqual(50, finding.line)
        self.assertEqual("FG_R00029", finding.vuln_id_from_tool)
        self.assertEqual("FG_R00029:aws_cloudtrail.audit", finding.unique_id_from_tool)
        self.assertEqual("https://docs.fugue.co/FG_R00029.html", finding.references)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Rule:** tf_aws_cloudtrail_cloudwatch", finding.description)
        self.assertIn("**Resource:** aws_cloudtrail.audit", finding.description)
        self.assertIn("**Provider:** aws", finding.description)
        self.assertIn("CIS-AWS_v1.4.0_3.4", finding.description)

        self.assertEqual(
            ["provider:aws", "resource:aws_cloudtrail", "input:tf",
             "family:CIS-AWS_v1.2.0", "family:CIS-AWS_v1.3.0", "family:CIS-AWS_v1.4.0"],
            finding.unsaved_tags,
        )

    def test_only_failed_rules_are_imported(self):
        """
        The point of this parser: Regula reports every rule it evaluated, passes included.

        This fixture is a real run over a five-resource Terraform file - 62 rule results, of which
        40 PASSED. A PASS is the tool confirming nothing is wrong; importing those would fill
        DefectDojo with items nobody can action.
        """
        raw = json.loads(self.scan("regula_many_vuln.json").read_text(encoding="utf-8"))
        results = raw["rule_results"]
        self.assertEqual(62, len(results))
        self.assertEqual(40, sum(1 for r in results if r["rule_result"] == "PASS"))
        self.assertEqual(22, sum(1 for r in results if r["rule_result"] == "FAIL"))

        findings = self.parse("regula_many_vuln.json")
        self.assertEqual(22, len(findings))

    def test_a_waived_rule_is_not_a_finding(self):
        """WAIVED means the operator already excluded the rule deliberately."""
        report = io.StringIO(json.dumps({"rule_results": [
            {"rule_result": "WAIVED", "rule_id": "FG_R00001", "resource_id": "a.b",
             "rule_summary": "waived", "rule_severity": "High"},
            {"rule_result": "FAIL", "rule_id": "FG_R00002", "resource_id": "a.c",
             "rule_summary": "failed", "rule_severity": "High"},
        ]}))
        findings = list(RegulaParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("failed", findings[0].title)

    def test_severity_is_regulas_own_grading(self):
        """
        Regula grades its own rules, so nothing is invented here.

        Asserted against the raw fixture so a future change that starts deriving severity from the
        rule id or the resource type is caught.
        """
        raw = json.loads(self.scan("regula_many_vuln.json").read_text(encoding="utf-8"))
        fail_severities = {r["rule_severity"] for r in raw["rule_results"] if r["rule_result"] == "FAIL"}
        self.assertEqual({"Critical", "High", "Medium", "Low"}, fail_severities)

        findings = self.parse("regula_many_vuln.json")
        counts = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        self.assertEqual({"Critical": 1, "High": 8, "Medium": 11, "Low": 2}, counts)

    def test_the_critical_finding_is_the_publicly_readable_bucket(self):
        finding = self.by_uid("regula_many_vuln.json")["FG_R00277:aws_s3_bucket.artifacts"]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("S3 buckets should not be publicly readable", finding.title)
        self.assertEqual("aws_s3_bucket", finding.component_name)

    def test_the_severity_mapping_directly(self):
        """
        Informational and Unknown are not present in the fixture, so they are covered here.

        Regula emits Unknown for a rule with no severity set, including custom rules. Those are real
        policy failures, so they become Medium rather than Info.
        """
        parser = RegulaParser()
        for value, expected in [
            ("Critical", "Critical"), ("High", "High"), ("Medium", "Medium"), ("Low", "Low"),
            ("Informational", "Info"), ("informational", "Info"),
            ("Unknown", "Medium"), ("", "Medium"),
        ]:
            self.assertEqual(expected, parser.severity({"rule_severity": value}), value)

    def test_the_same_rule_against_several_resources_stays_several_findings(self):
        """
        A rule commonly fails against more than one resource, and each is its own problem.

        The identity is the rule/resource pair, so these must not collapse into one finding.
        """
        report = io.StringIO(json.dumps({"rule_results": [
            {"rule_result": "FAIL", "rule_id": "FG_R00277", "resource_id": "aws_s3_bucket.one",
             "resource_type": "aws_s3_bucket", "rule_summary": "public bucket", "rule_severity": "Critical"},
            {"rule_result": "FAIL", "rule_id": "FG_R00277", "resource_id": "aws_s3_bucket.two",
             "resource_type": "aws_s3_bucket", "rule_summary": "public bucket", "rule_severity": "Critical"},
        ]}))
        findings = list(RegulaParser().get_findings(report, Test()))
        self.assertEqual(2, len(findings))
        self.assertEqual(
            {"FG_R00277:aws_s3_bucket.one", "FG_R00277:aws_s3_bucket.two"},
            {f.unique_id_from_tool for f in findings},
        )

    def test_the_same_rule_and_resource_twice_collapses(self):
        """Several compliance families can map to one rule; the pair is still one failure."""
        result = {"rule_result": "FAIL", "rule_id": "FG_R00277", "resource_id": "aws_s3_bucket.one",
                  "rule_summary": "public bucket", "rule_severity": "Critical"}
        report = io.StringIO(json.dumps({"rule_results": [result, result]}))
        self.assertEqual(1, len(list(RegulaParser().get_findings(report, Test()))))

    def test_a_bare_results_array_is_accepted(self):
        report = io.StringIO(json.dumps([
            {"rule_result": "FAIL", "rule_id": "FG_R00001", "resource_id": "a.b",
             "rule_summary": "failed", "rule_severity": "Low"},
        ]))
        self.assertEqual(1, len(list(RegulaParser().get_findings(report, Test()))))

    def test_a_result_with_no_summary_falls_back_to_the_rule_name(self):
        report = io.StringIO(json.dumps({"rule_results": [
            {"rule_result": "FAIL", "rule_id": "FG_R00001", "resource_id": "a.b",
             "rule_name": "tf_aws_something", "rule_severity": "Low"},
        ]}))
        self.assertEqual("tf_aws_something", list(RegulaParser().get_findings(report, Test()))[0].title)

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(RegulaParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("rule_results", str(raised.exception))
