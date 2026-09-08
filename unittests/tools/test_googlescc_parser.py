import io
import json

from dojo.models import Finding, Test
from dojo.tools.googlescc.parser import GoogleSCCParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGoogleSCCParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("googlescc") / filename).open(encoding="utf-8") as file:
            return list(GoogleSCCParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal ScanTypeName in the Google Cloud SCC connector verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = GoogleSCCParser()
        self.assertEqual(["Google Cloud SCC - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Google Cloud SCC - Connectors Import",
            parser.get_label_for_scan_types("Google Cloud SCC - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("googlescc_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("googlescc_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring toFinding in the connector's converter."""
        findings = self.parse("googlescc_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("PUBLIC_BUCKET_ACL - generic-app-assets", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        # The SCC category is its rule identifier.
        self.assertEqual("PUBLIC_BUCKET_ACL", finding.vuln_id_from_tool)
        self.assertEqual(
            "organizations/000000000001/sources/000000000002/findings/aaaa1111",
            finding.unique_id_from_tool,
        )
        self.assertEqual(
            "https://console.example.com/storage/browser/generic-app-assets", finding.url,
        )

        self.assertIn("The bucket grants access to allUsers.", finding.description)
        self.assertIn("**Finding class:** MISCONFIGURATION", finding.description)
        self.assertIn(
            "**Resource:** google.cloud.storage.Bucket //storage.googleapis.com/generic-app-assets",
            finding.description,
        )
        self.assertIn("**Reference:** https://console.example.com/", finding.description)

    def test_the_finding_and_the_resource_are_siblings_not_nested(self):
        """
        SCC's ListFindings pairs each finding with the resource it was found on, side by side.

        The resource carries the display name and type that make the finding readable, so reading only
        the finding half would lose them - and reading the result as if it were the finding would find
        nothing at all.
        """
        raw = json.loads((get_unit_tests_scans_path("googlescc")
                          / "googlescc_one_vuln.json").read_text(encoding="utf-8"))
        result = raw["listFindingsResults"][0]
        self.assertIn("finding", result)
        self.assertIn("resource", result)
        self.assertNotIn("resource", result["finding"])
        self.assertNotIn("displayName", result["finding"])

        finding = self.parse("googlescc_one_vuln.json")[0]
        # The display name comes from the resource half, the category from the finding half.
        self.assertEqual("PUBLIC_BUCKET_ACL - generic-app-assets", finding.title)

    def test_the_title_is_the_category_alone_when_the_resource_has_no_display_name(self):
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/cccc3333"
        ]
        self.assertEqual("OS_VULNERABILITY", finding.title)

    def test_a_finding_with_no_category_is_named_by_the_connectors_fallback(self):
        """SCC does not always set a category, and an empty title would be useless in the finding list."""
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/dddd4444"
        ]
        self.assertEqual("Security Command Center finding", finding.title)
        self.assertIsNone(finding.vuln_id_from_tool)

    def test_severity_unspecified_is_info(self):
        """SCC's own SEVERITY_UNSPECIFIED is not a DefectDojo severity and falls through."""
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/dddd4444"
        ]
        self.assertEqual("Info", finding.severity)

    def test_the_severity_ladder(self):
        findings = self.by_uid("googlescc_many_vuln.json")
        base = "organizations/000000000001/sources/000000000002/findings/"
        self.assertEqual("High", findings[base + "aaaa1111"].severity)
        self.assertEqual("Critical", findings[base + "bbbb2222"].severity)
        self.assertEqual("Medium", findings[base + "cccc3333"].severity)
        self.assertEqual("Low", findings[base + "eeee5555"].severity)

    def test_a_vulnerability_class_finding_carries_its_cve_and_score(self):
        """
        SCC reports several finding classes and only some carry a CVE, nested two objects deep.

        A misconfiguration finding has no vulnerability block at all, so the lookup has to tolerate
        that rather than assuming every finding has one.
        """
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/bbbb2222"
        ]
        self.assertEqual(["CVE-2000-0001"], finding.unsaved_vulnerability_ids)
        self.assertEqual(9.8, finding.cvssv3_score)

    def test_a_misconfiguration_finding_has_no_cve(self):
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/aaaa1111"
        ]
        self.assertIsNone(finding.unsaved_vulnerability_ids)
        self.assertIsNone(finding.cvssv3_score)

    def test_a_cve_with_a_zero_score_records_the_cve_but_no_score(self):
        """The connector only sets the score when it is above zero."""
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/cccc3333"
        ]
        self.assertEqual(["CVE-2000-0002"], finding.unsaved_vulnerability_ids)
        self.assertIsNone(finding.cvssv3_score)

    def test_an_empty_vulnerability_block_is_tolerated(self):
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/eeee5555"
        ]
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_a_finding_with_no_external_uri_has_no_url_or_reference_line(self):
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/bbbb2222"
        ]
        self.assertIsNone(finding.url)
        self.assertNotIn("**Reference:**", finding.description)

    def test_the_resource_line_is_omitted_when_there_is_nothing_to_show(self):
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/dddd4444"
        ]
        self.assertNotIn("**Resource:**", finding.description)

    def test_the_resource_line_shows_whichever_parts_exist(self):
        """The type and name are space-joined, and either may be missing."""
        finding = self.by_uid("googlescc_many_vuln.json")[
            "organizations/000000000001/sources/000000000002/findings/cccc3333"
        ]
        self.assertIn(
            "**Resource:** //compute.googleapis.com/projects/p/instances/other-vm",
            finding.description,
        )

    def test_a_flattened_export_is_accepted(self):
        report = io.StringIO(json.dumps({"listFindingsResults": [{
            "name": "organizations/1/sources/2/findings/f1",
            "category": "PUBLIC_BUCKET_ACL",
            "severity": "HIGH",
            "description": "Flattened.",
            "resource": {"displayName": "a-bucket", "type": "google.cloud.storage.Bucket"},
        }]}))
        finding = list(GoogleSCCParser().get_findings(report, Test()))[0]
        self.assertEqual("PUBLIC_BUCKET_ACL - a-bucket", finding.title)
        self.assertEqual("High", finding.severity)

    def test_a_result_with_no_finding_half_is_skipped(self):
        report = io.StringIO(json.dumps({"listFindingsResults": [
            {"resource": {"displayName": "orphan"}},
            {"finding": {"name": "n1", "category": "C", "severity": "LOW"}},
        ]}))
        findings = list(GoogleSCCParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("C", findings[0].title)

    def test_a_bare_array_is_accepted(self):
        report = io.StringIO(json.dumps([
            {"finding": {"name": "n1", "category": "C", "severity": "LOW"}},
        ]))
        self.assertEqual(1, len(list(GoogleSCCParser().get_findings(report, Test()))))

    def test_a_repeated_finding_name_collapses(self):
        row = {"finding": {"name": "same", "category": "C", "severity": "LOW"}}
        report = io.StringIO(json.dumps({"listFindingsResults": [row, row]}))
        self.assertEqual(1, len(list(GoogleSCCParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(GoogleSCCParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("listFindingsResults", str(raised.exception))
