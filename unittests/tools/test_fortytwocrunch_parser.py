import io
import json

from dojo.models import Finding, Test
from dojo.tools.fortytwocrunch.parser import FortytwocrunchParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFortytwocrunchParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("fortytwocrunch") / filename
        with path.open(encoding="utf-8") as file:
            return list(FortytwocrunchParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(FortytwocrunchParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def audit(self, index=None, **group):
        row = {"criticality": 4, "description": "An issue", "issues": [{"pointer": 0}]}
        row.update(group)
        return {"apiId": "api-1",
                "report": {"index": index if index is not None else ["/paths/~1x/get"],
                           "security": {"issues": {"issue-1": row}}}}

    def scan(self, issue=None, templates=None, pointers=None):
        return {"apiId": "api-1", "report": {"data": {
            "index": {"jsonPointers": pointers if pointers is not None else ["/paths/~1x/get"],
                      "injectionDescriptions": templates if templates is not None else ["A problem"]},
            "paths": {"/x": {"get": {"issues": [issue or {"criticality": 4,
                                                          "injectionDescription": 0}]}}}}}}

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """Must equal the 42Crunch connector's ScanTypeName verbatim."""
        parser = FortytwocrunchParser()
        self.assertEqual(["42Crunch - Connectors Import"], parser.get_scan_types())
        self.assertEqual("42Crunch - Connectors Import",
                         parser.get_label_for_scan_types("42Crunch - Connectors Import"))

    def test_this_scan_type_has_no_curated_dedupe_fields(self):
        """No hash-field list to copy, so it uses DefectDojo's default algorithm - as the connector does."""
        self.assertFalse(hasattr(FortytwocrunchParser(), "get_dedupe_fields"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("fortytwocrunch_no_vuln.json")))

    def test_audit_one_vuln(self):
        self.assertEqual(1, len(self.parse("fortytwocrunch_audit_one_vuln.json")))

    def test_audit_one_vuln_field_mapping(self):
        """Full field mapping, mirroring auditFinding in the connector's converter."""
        findings = self.parse("fortytwocrunch_audit_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("The API key is passed in a header, which is exposed to intermediaries",
                         finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("api-0001/audit/v3-global-securityscheme-apikey-inheader/"
                         "/paths/~1orders/get/security", finding.unique_id_from_tool)
        self.assertEqual("v3-global-securityscheme-apikey-inheader", finding.vuln_id_from_tool)
        self.assertEqual("/paths/~1orders/get/security", finding.file_path)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["42crunch", "audit", "security"], finding.unsaved_tags)
        self.assertEqual(
            "The GET /orders operation accepts an API key in a request header\n\n"
            "* **Category:** security\n"
            "* **OpenAPI location:** /paths/~1orders/get/security\n",
            finding.description,
        )
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))

    def test_the_title_and_the_description_paragraph_use_opposite_precedence(self):
        """
        The title prefers the SHARED issue description; the paragraph prefers the SPECIFIC one.

        That is deliberate in the connector: the title groups occurrences of one issue type under one
        name, while the body says what is wrong at this particular location.
        """
        finding = self.parse("fortytwocrunch_audit_one_vuln.json")[0]
        self.assertEqual("The API key is passed in a header, which is exposed to intermediaries",
                         finding.title)
        self.assertTrue(finding.description.startswith(
            "The GET /orders operation accepts an API key in a request header"))

    def test_the_title_falls_back_to_the_specific_description_then_the_issue_id(self):
        findings = self.parse_string(self.audit(description="",
                                                issues=[{"pointer": 0,
                                                         "specificDescription": "Specific"}]))
        self.assertEqual("Specific", findings[0].title)
        findings = self.parse_string(self.audit(description="", issues=[{"pointer": 0}]))
        self.assertEqual("issue-1", findings[0].title)

    def test_audit_many_vuln(self):
        """
        Every category contributes, and one issue type with two occurrences is two findings.

        Six issue types across the five sections, one of them firing twice.
        """
        self.assertEqual(7, len(self.parse("fortytwocrunch_audit_many_vuln.json")))

    def test_every_audit_category_is_read_with_its_own_label(self):
        findings = self.parse("fortytwocrunch_audit_many_vuln.json")
        categories = {tag for finding in findings for tag in finding.unsaved_tags}
        for expected in ("security", "data-validation", "warning", "semantic-error",
                         "validation-error"):
            self.assertIn(expected, categories)

    def test_two_occurrences_of_one_issue_type_are_two_findings(self):
        """
        One audit issue can fire at several places in the definition, and each is its own fix.

        Their identities differ by the resolved OpenAPI location.
        """
        uids = set(self.by_uid("fortytwocrunch_audit_many_vuln.json"))
        self.assertIn("api-0001/audit/v3-global-securityscheme-apikey-inheader/"
                      "/paths/~1orders/get/security", uids)
        self.assertIn("api-0001/audit/v3-global-securityscheme-apikey-inheader/"
                      "/paths/~1orders/post/requestBody", uids)

    def test_an_unresolvable_pointer_keeps_the_raw_index_in_the_identity(self):
        """
        Without it, two occurrences of one issue with no location would collapse into one finding.

        The location is out of range here, so there is nothing to resolve - but the occurrences are
        still distinct things.
        """
        findings = self.by_uid("fortytwocrunch_audit_many_vuln.json")
        self.assertIn("api-0001/audit/v3-operation-securityscheme-missing/#99", findings)
        self.assertIsNone(findings["api-0001/audit/v3-operation-securityscheme-missing/#99"].file_path)

    def test_a_negative_pointer_is_also_unresolvable(self):
        findings = self.by_uid("fortytwocrunch_audit_many_vuln.json")
        self.assertIn("api-0001/audit/v3-validation-broken/#-1", findings)

    def test_criticality_five_is_the_most_severe(self):
        """42Crunch grades 1 as informational and 5 as critical - a scale, not an inverse one."""
        for criticality, expected in ((5, "Critical"), (4, "High"), (3, "Medium"), (2, "Low"),
                                      (1, "Info"), (0, "Info"), (9, "Info"), (None, "Info")):
            with self.subTest(criticality=criticality):
                findings = self.parse_string(self.audit(criticality=criticality))
                self.assertEqual(expected, findings[0].severity)

    def test_the_openapi_location_is_the_file_path(self):
        """An audit finding is a place in a definition, so the JSON Pointer is its path."""
        finding = self.by_uid("fortytwocrunch_audit_many_vuln.json")[
            "api-0001/audit/v3-schema-response-string-maxlength//paths/~1orders~1{id}/get/responses/200"]
        self.assertEqual("/paths/~1orders~1{id}/get/responses/200", finding.file_path)

    def test_scan_many_vuln(self):
        self.assertEqual(4, len(self.parse("fortytwocrunch_scan_many_vuln.json")))

    def test_scan_field_mapping(self):
        """Full field mapping, mirroring scanFinding in the connector's converter."""
        finding = self.by_uid("fortytwocrunch_scan_many_vuln.json")["api-0001/scan/GET /orders/0"]

        self.assertEqual("The response returned 500 instead of the documented 200", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("curl -X GET 'https://api.example.com/orders?limit=1'",
                         finding.steps_to_reproduce)
        self.assertTrue(finding.active)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(["42crunch", "scan", "GET"], finding.unsaved_tags)
        self.assertEqual(
            "The response returned 500 instead of the documented 200\n\n"
            "* **Operation:** GET /orders\n"
            "* **URL:** https://api.example.com/orders?limit=1\n"
            "* **Response status:** 500\n"
            "* **OpenAPI location:** /paths/~1orders/get/responses/200\n",
            finding.description,
        )

    def test_the_scan_description_is_a_template_filled_from_a_separate_parameter_list(self):
        """
        The description is referenced by integer and its parameters arrive separately.

        Each "%s" is filled in turn, one substitution per parameter. Reading the integer alone would
        leave the finding with no description at all.
        """
        findings = self.parse_string(self.scan(
            templates=["saw %s, expected %s, at %s"],
            issue={"criticality": 3, "injectionDescription": 0,
                   "injectionDescriptionParams": ["500", "200"]}))
        self.assertEqual("saw 500, expected 200, at %s", findings[0].title)

    def test_a_template_with_no_parameters_is_used_as_it_is(self):
        finding = self.by_uid("fortytwocrunch_scan_many_vuln.json")["api-0001/scan/GET /orders/1"]
        self.assertEqual("The operation accepted a request with no authentication", finding.title)

    def test_an_unresolvable_description_falls_back_to_the_operation(self):
        finding = self.by_uid("fortytwocrunch_scan_many_vuln.json")["api-0001/scan/GET /health/99"]
        self.assertEqual("GET /health", finding.title)
        self.assertNotIn("* **OpenAPI location:**", finding.description)

    def test_the_scan_identity_avoids_the_per_scan_uuid(self):
        """
        A scan issue's own id is a per-scan UUID, so it is not stable across scans.

        The identity is the operation plus the check index instead - the same for the same issue - so
        rescanning updates a finding rather than creating a new one every time.
        """
        findings = self.parse("fortytwocrunch_scan_many_vuln.json")
        for finding in findings:
            self.assertNotIn("3f8b0c1e", finding.unique_id_from_tool)
        self.assertEqual(
            ["api-0001/scan/GET /health/99", "api-0001/scan/GET /orders/0",
             "api-0001/scan/GET /orders/1", "api-0001/scan/POST /orders/2"],
            sorted(finding.unique_id_from_tool for finding in findings),
        )

    def test_the_method_is_uppercased_in_the_operation_and_the_tag(self):
        findings = self.parse_string(self.scan())
        self.assertIn("* **Operation:** GET /x", findings[0].description)
        self.assertIn("GET", findings[0].unsaved_tags)

    def test_a_response_status_of_zero_is_not_reported(self):
        finding = self.by_uid("fortytwocrunch_scan_many_vuln.json")["api-0001/scan/POST /orders/2"]
        self.assertNotIn("* **Response status:**", finding.description)
        self.assertIsNone(finding.steps_to_reproduce)

    def test_the_endpoint_is_the_url_origin_only(self):
        """
        A conformance scan hits many paths on one host, and the operation is already in the identity.

        So the endpoint carries the scheme and host, with no path - which is what the connector
        records.
        """
        finding = self.by_uid("fortytwocrunch_scan_many_vuln.json")["api-0001/scan/GET /orders/0"]
        locations = self.get_unsaved_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual("api.example.com", locations[0].host)
        self.assertEqual("https", locations[0].protocol)
        self.assertFalse(locations[0].path)
        self.assertFalse(locations[0].query)

    def test_a_url_that_is_not_a_url_adds_no_endpoint(self):
        """
        A host DefectDojo rejects makes Endpoint.clean() raise, which fails the WHOLE import.

        The URL is still in the description, so nothing is lost by declining to build an endpoint.
        """
        finding = self.by_uid("fortytwocrunch_scan_many_vuln.json")["api-0001/scan/GET /health/99"]
        self.assertEqual(0, len(self.get_unsaved_locations(finding)))
        self.assertIn("* **URL:** not a url at all", finding.description)

    def test_a_url_with_no_scheme_adds_no_endpoint(self):
        """The connector requires both a scheme and a host before it records an origin."""
        findings = self.parse_string(self.scan(issue={"criticality": 3, "injectionDescription": 0,
                                                      "url": "api.example.com/orders"}))
        self.assertEqual(0, len(self.get_unsaved_locations(findings[0])))

    def test_a_url_naming_a_port_keeps_it(self):
        findings = self.parse_string(self.scan(issue={"criticality": 3, "injectionDescription": 0,
                                                      "url": "https://api.example.com:8443/orders"}))
        locations = self.get_unsaved_locations(findings[0])
        self.assertEqual(8443, locations[0].port)

    def test_the_two_report_types_are_told_apart_by_shape(self):
        """
        42Crunch produces an audit of the definition and a scan of the running API.

        Both convert under one scan type, and a file is one or the other - so the shape decides: a
        scan report has a per-path issue tree, an audit report has an index table and its sections.
        """
        audit = self.parse("fortytwocrunch_audit_one_vuln.json")[0]
        self.assertTrue(audit.static_finding)
        self.assertFalse(audit.dynamic_finding)
        self.assertIn("audit", audit.unsaved_tags)

        scan = self.parse("fortytwocrunch_scan_many_vuln.json")[0]
        self.assertFalse(scan.static_finding)
        self.assertTrue(scan.dynamic_finding)
        self.assertIn("scan", scan.unsaved_tags)

    def test_an_unwrapped_report_is_accepted(self):
        """A report downloaded as-is has no wrapper, and then it carries no API id either."""
        payload = {"index": ["/paths/~1x/get"],
                   "security": {"issues": {"issue-1": {"criticality": 4, "description": "An issue",
                                                       "issues": [{"pointer": 0}]}}}}
        findings = self.parse_string(payload)
        self.assertEqual(1, len(findings))
        self.assertEqual("/audit/issue-1//paths/~1x/get", findings[0].unique_id_from_tool)

    def test_the_api_id_may_be_spelled_three_ways(self):
        """
        The API id is part of every identity the connector builds and a report does not carry it.

        Without it a file import will not deduplicate against synced findings, so all the spellings a
        user might reach for are accepted.
        """
        for key in ("apiId", "api_id", "apiID"):
            with self.subTest(key=key):
                payload = self.audit()
                payload.pop("apiId")
                payload[key] = "api-9"
                findings = self.parse_string(payload)
                self.assertTrue(findings[0].unique_id_from_tool.startswith("api-9/audit/"))

    def test_a_long_title_is_truncated_with_an_ellipsis(self):
        long_description = "x" * 300
        findings = self.parse_string(self.audit(description=long_description))
        self.assertEqual(250, len(findings[0].title))
        self.assertTrue(findings[0].title.endswith("..."))
        # The full text is still in the body.
        self.assertIn(long_description, findings[0].description)

    def test_a_title_at_the_limit_is_not_truncated(self):
        exact = "x" * 250
        findings = self.parse_string(self.audit(description=exact))
        self.assertEqual(exact, findings[0].title)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string(["not a report"])
        self.assertIn("42Crunch", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("Conformance Scan", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        audit = {"apiId": "api-1", "report": {"index": ["/paths/~1x/get"], "security": {"issues": {
            "issue-bad": "not an object",
            "issue-no-list": {"criticality": 4, "issues": "not a list"},
            "issue-1": {"criticality": 4, "description": "An issue",
                        "issues": ["not an object", None, {"pointer": 0}]},
        }}}}
        findings = self.parse_string(audit)
        self.assertEqual(1, len(findings))
        self.assertEqual("api-1/audit/issue-1//paths/~1x/get", findings[0].unique_id_from_tool)

    def test_malformed_scan_rows_are_skipped(self):
        scan = {"apiId": "api-1", "report": {"data": {
            "index": {"jsonPointers": [], "injectionDescriptions": ["A problem"]},
            "paths": {"/x": {"get": {"issues": ["not an object", None,
                                                {"criticality": 3, "injectionDescription": 0}]},
                             "post": "not an object"},
                      "/y": "not an object"}}}}
        findings = self.parse_string(scan)
        self.assertEqual(1, len(findings))
        self.assertEqual("api-1/scan/GET /x/0", findings[0].unique_id_from_tool)

    def test_severity_is_always_a_known_value(self):
        for filename in ("fortytwocrunch_audit_many_vuln.json", "fortytwocrunch_audit_one_vuln.json",
                         "fortytwocrunch_scan_many_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
