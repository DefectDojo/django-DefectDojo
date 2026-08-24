import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.datadog.parser import DatadogParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDatadogParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("datadog") / filename).open(encoding="utf-8") as file:
            return list(DatadogParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(DatadogParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def row(self, attributes, tags=None, identifier="row-1"):
        return {"data": [{"id": identifier, "attributes": {"tags": tags or [], "attributes": attributes}}]}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Datadog connector's ScanTypeName verbatim.

        Note it does NOT follow the "<Vendor> - Connectors Import" pattern the other connector scan
        types use, so it cannot be derived - it has to be copied.
        """
        parser = DatadogParser()
        self.assertEqual(["Datadog Cloud Security"], parser.get_scan_types())
        self.assertEqual("Datadog Cloud Security", parser.get_label_for_scan_types("Datadog Cloud Security"))
        self.assertNotIn("Datadog - Connectors Import", parser.get_scan_types())

    def test_no_vuln(self):
        """
        Every row in this sample is one Datadog has already dealt with.

        Muted by status, muted through the workflow, a compliance rule that passed, resolved and
        auto-closed - five different ways of saying "not actionable", and all five are honoured or a
        triaged queue comes straight back.
        """
        self.assertEqual(0, len(self.parse("datadog_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("datadog_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("datadog_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("openssl 3.0.2 is affected by CVE-2000-0001", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("AAAAA-BBBB-CCCC-0001", finding.unique_id_from_tool)
        self.assertEqual("rule-0001", finding.vuln_id_from_tool)
        self.assertEqual("openssl", finding.component_name)
        self.assertEqual("3.0.2", finding.component_version)
        self.assertEqual("payments-api", finding.service)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        # The base severity details win over the adjusted ones, and both values come from the same block.
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["CVE-2000-0001", "GHSA-aaaa-bbbb-cccc"], finding.unsaved_vulnerability_ids)

        self.assertEqual(
            "## Overview\n\n"
            "The installed openssl build is affected by a memory-safety flaw.\n"
            "* **Rule:** Vulnerable library detected\n"
            "* **Finding type:** vulnerability\n"
            "* **Resource:** web-node-1 (aws_ec2_instance)\n"
            "* **Advisory:** CVE-2000-0001\n"
            "* **Advisory summary:** Memory-safety flaw in openssl.\n",
            finding.description,
        )
        self.assertEqual(
            ["datadog", "finding_type:vulnerability", "cloud_provider:aws", "region:us-east-1",
             "account:acct-1234", "resource_type:aws_ec2_instance", "service:payments-api",
             "env:prod", "team:platform"],
            finding.unsaved_tags,
        )

    def test_many_vuln(self):
        """Seven rows, three of them already dealt with."""
        self.assertEqual(4, len(self.parse("datadog_many_vuln.json")))

    def test_each_way_of_saying_not_actionable(self):
        for status in ("muted", "resolved", "auto_closed", "MUTED", " resolved "):
            with self.subTest(status=status):
                self.assertEqual(0, len(self.parse_string(self.row({
                    "finding_type": "misconfiguration", "title": "A finding", "severity": "high",
                    "status": status,
                }))))

        self.assertEqual(0, len(self.parse_string(self.row({
            "finding_type": "misconfiguration", "title": "A finding", "severity": "high",
            "status": "open", "workflow": {"mute": {"is_muted": True}},
        }))))
        self.assertEqual(0, len(self.parse_string(self.row({
            "finding_type": "misconfiguration", "title": "A finding", "severity": "high",
            "status": "open", "compliance": {"evaluation": "PASS"},
        }))))

    def test_a_failing_compliance_rule_is_imported(self):
        """Only a passing evaluation is silence; a failing one is the finding."""
        findings = self.by_uid("datadog_many_vuln.json")
        self.assertIn("AAAAA-BBBB-CCCC-0002", findings)
        self.assertIn("* **Compliance evaluation:** fail", findings["AAAAA-BBBB-CCCC-0002"].description)

    def test_severity_labels(self):
        for label, expected in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                                ("low", "Low"), ("CRITICAL", "Critical"), ("unknown", "Info"),
                                ("", "Info")):
            with self.subTest(label=label):
                findings = self.parse_string(self.row({
                    "finding_type": "misconfiguration", "title": "A finding", "severity": label,
                    "status": "open",
                }))
                self.assertEqual(expected, findings[0].severity)

    def test_base_severity_is_not_used_for_the_grade(self):
        """
        Datadog's base_severity is the rule's default before it adjusts for the environment.

        The adjusted `severity` is the one worth importing, so a row whose base says high and whose
        severity says critical is Critical.
        """
        finding = self.parse("datadog_one_vuln.json")[0]
        self.assertEqual("Critical", finding.severity)

    def test_runtime_finding_types_are_dynamic(self):
        """
        Datadog returns everything through one endpoint, so static-versus-dynamic is per row.

        A runtime or API-security finding is something Datadog watched happen; a misconfiguration or a
        library vulnerability is something it read.
        """
        for finding_type, static in (("api_security", False), ("attack_path", False),
                                     ("runtime_code_vulnerability", False), ("workload_activity", False),
                                     ("identity_risk", False), ("misconfiguration", True),
                                     ("vulnerability", True), ("", True)):
            with self.subTest(finding_type=finding_type):
                findings = self.parse_string(self.row({
                    "finding_type": finding_type, "title": "A finding", "severity": "high",
                    "status": "open",
                }))
                self.assertEqual(static, findings[0].static_finding)
                self.assertEqual(not static, findings[0].dynamic_finding)

    def test_title_falls_back_to_the_rule_then_the_finding_type(self):
        findings = self.by_uid("datadog_many_vuln.json")
        self.assertEqual("S3 bucket should not allow public reads", findings["AAAAA-BBBB-CCCC-0002"].title)
        self.assertEqual("Datadog finding: attack_path", findings["AAAAA-BBBB-CCCC-0007"].title)

        bare = self.parse_string(self.row({"severity": "low", "status": "open"}))
        self.assertEqual("Datadog security finding", bare[0].title)

    def test_the_unique_id_falls_back_to_the_finding_id(self):
        """Datadog repeats the id inside the attributes, which is the fallback when the row has none."""
        findings = self.by_uid("datadog_many_vuln.json")
        self.assertIn("finding-0003", findings)
        self.assertEqual("Unauthenticated endpoint accepts writes", findings["finding-0003"].title)

    def test_dates_are_unix_milliseconds(self):
        """
        Datadog timestamps in milliseconds, not seconds.

        Reading them as seconds would date every finding in 1970.
        """
        findings = self.by_uid("datadog_many_vuln.json")
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), findings["AAAAA-BBBB-CCCC-0001"].date)
        self.assertEqual(datetime(2024, 6, 1, tzinfo=UTC).date(), findings["AAAAA-BBBB-CCCC-0002"].date)
        # No first_seen_at, so the detection-changed timestamp stands in.
        self.assertEqual(datetime(2024, 7, 15, tzinfo=UTC).date(), findings["finding-0003"].date)

    def test_a_row_with_no_timestamp_keeps_the_default_date(self):
        findings = self.parse_string(self.row({
            "finding_type": "misconfiguration", "title": "A finding", "severity": "low", "status": "open",
        }))
        self.assertEqual(datetime.now(tz=UTC).date(), findings[0].date)

    def test_cvss_prefers_the_base_block_and_takes_both_values_together(self):
        """
        Mixing a vector from one block with a score from the other would describe a scoring that never
        existed, so the first block carrying either value supplies both.
        """
        findings = self.parse_string(self.row({
            "finding_type": "vulnerability", "title": "A finding", "severity": "high", "status": "open",
            "severity_details": {"adjusted": {"score": 7.2, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},
        }))
        self.assertEqual(7.2, findings[0].cvssv3_score)
        self.assertEqual("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", findings[0].cvssv3)

    def test_no_severity_details_leaves_the_cvss_unset(self):
        findings = self.by_uid("datadog_many_vuln.json")
        self.assertIsNone(findings["AAAAA-BBBB-CCCC-0002"].cvssv3)
        self.assertIsNone(findings["AAAAA-BBBB-CCCC-0002"].cvssv3_score)

    def test_vulnerability_ids_come_from_the_advisory_and_the_prose(self):
        """
        Datadog names the CVE in the advisory for some finding types and only in the text for others.

        Both are read, duplicates dropped, order preserved - and the identifier set is the
        connector's: CVE, GHSA, Go and RHSA.
        """
        finding = self.parse("datadog_one_vuln.json")[0]
        self.assertEqual(["CVE-2000-0001", "GHSA-aaaa-bbbb-cccc"], finding.unsaved_vulnerability_ids)

        findings = self.parse_string(self.row({
            "finding_type": "vulnerability", "status": "open", "severity": "high",
            "title": "GO-2024-1234 in a module",
            "description": "See also RHSA-2024:1234 and GHSA-dddd-eeee-ffff.",
        }))
        self.assertEqual(
            ["GO-2024-1234", "RHSA-2024:1234", "GHSA-dddd-eeee-ffff"],
            findings[0].unsaved_vulnerability_ids,
        )

    def test_a_finding_with_no_identifiers_has_none(self):
        findings = self.by_uid("datadog_many_vuln.json")
        self.assertIsNone(findings["AAAAA-BBBB-CCCC-0002"].unsaved_vulnerability_ids)

    def test_the_resource_label_falls_back_to_the_resource_id(self):
        findings = self.by_uid("datadog_many_vuln.json")
        self.assertIn(
            "* **Resource:** arn:aws:s3:::example-bucket (aws_s3_bucket)",
            findings["AAAAA-BBBB-CCCC-0002"].description,
        )

    def test_tags_are_deduplicated_but_not_sorted(self):
        """
        The connector preserves the order it built the tags in.

        Sorting them would be tidier and wrong: a tag list that reorders on every sync reads as a
        change to the finding.
        """
        finding = self.parse("datadog_one_vuln.json")[0]
        self.assertEqual("datadog", finding.unsaved_tags[0])
        self.assertEqual("finding_type:vulnerability", finding.unsaved_tags[1])
        self.assertEqual(len(set(finding.unsaved_tags)), len(finding.unsaved_tags))
        self.assertNotEqual(sorted(finding.unsaved_tags), finding.unsaved_tags)

    def test_the_service_comes_out_of_datadogs_own_tag(self):
        finding = self.parse("datadog_one_vuln.json")[0]
        self.assertEqual("payments-api", finding.service)

        findings = self.parse_string(self.row({
            "finding_type": "misconfiguration", "title": "A finding", "severity": "low", "status": "open",
        }, tags=["env:prod"]))
        self.assertIsNone(findings[0].service)

    def test_export_shapes(self):
        attributes = {"finding_type": "misconfiguration", "title": "A finding", "severity": "low",
                      "status": "open"}
        row = {"id": "row-1", "attributes": {"tags": [], "attributes": attributes}}
        for payload in ({"data": [row]}, [row], row):
            with self.subTest(shape=type(payload).__name__):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Datadog", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("data", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"data": [
            "not an object",
            None,
            {"id": "no-attributes"},
            {"id": "empty-attributes", "attributes": {}},
            {"id": "row-1", "attributes": {"attributes": {"title": "A finding", "severity": "low",
                                                          "status": "open"}}},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("A finding", findings[0].title)

    def test_severity_is_always_a_known_value(self):
        for filename in ("datadog_many_vuln.json", "datadog_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
