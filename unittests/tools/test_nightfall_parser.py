import io
import json
from datetime import UTC, datetime

from dojo.models import Finding, Test
from dojo.tools.nightfall.parser import NightfallParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNightfallParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("nightfall") / filename).open(encoding="utf-8") as file:
            return list(NightfallParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(NightfallParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def by_uid(self, filename):
        return {finding.unique_id_from_tool: finding for finding in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the Nightfall AI connector's ScanType() verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every violation.
        """
        parser = NightfallParser()
        self.assertEqual(["Nightfall AI - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Nightfall AI - Connectors Import",
            parser.get_label_for_scan_types("Nightfall AI - Connectors Import"),
        )
        self.assertIn("Nightfall", parser.get_description_for_scan_types("Nightfall AI - Connectors Import"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("nightfall_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("nightfall_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring ViolationToFinding in the connector's converter."""
        findings = self.parse("nightfall_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "Verified live AWS credential exposed in GITHUB (example-org/generic-app:deploy/settings.py)",
            finding.title,
        )
        # The policy says High, but Nightfall verified the key works.
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(datetime(2024, 7, 1, tzinfo=UTC).date(), finding.date)
        self.assertEqual("vio_00000000000000000001", finding.unique_id_from_tool)
        self.assertEqual("Cloud credentials in source code", finding.vuln_id_from_tool)
        self.assertEqual("GITHUB", finding.service)
        self.assertEqual("deploy/settings.py", finding.file_path)
        self.assertEqual(42, finding.line)
        self.assertEqual("Nightfall risk score: 8.5 (source: POLICY)", finding.severity_justification)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertFalse(finding.out_of_scope)
        self.assertTrue(finding.verified)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["dlp", "GITHUB", "HIGH", "AWS"], finding.unsaved_tags)

        self.assertIn("**Integration:** GITHUB", finding.description)
        self.assertIn("**Location:** example-org/generic-app:deploy/settings.py", finding.description)
        self.assertIn("**Policies:** Cloud credentials in source code", finding.description)
        self.assertIn("**Nightfall state:** ACTIVE", finding.description)
        self.assertIn("**Resource owner:** example-user", finding.description)
        self.assertIn("**Redacted detections**", finding.description)
        self.assertIn("- AWS key (ACTIVE), redacted value `AKIA****REDACTED****`, confidence VERY_LIKELY, line 42",
                      finding.description)
        # The repository is private, so there is no exposure note.
        self.assertNotIn("**Exposure:**", finding.description)

        self.assertEqual(
            "https://app.example.com/violations/vio_00000000000000000001\n"
            "https://github.example.com/example-org/generic-app/blob/main/deploy/settings.py#L42",
            finding.references,
        )

    def test_mitigation_is_the_connectors_three_steps(self):
        finding = self.parse("nightfall_one_vuln.json")[0]
        steps = finding.mitigation.split("\n")
        self.assertEqual(3, len(steps))
        self.assertEqual("Remove or redact the sensitive data from the GITHUB resource.", steps[0])
        self.assertIn("Rotate any credential that was exposed", steps[1])
        self.assertIn("assume it is compromised", steps[1])
        self.assertIn("Review who had access", steps[2])

    def test_many_vuln(self):
        self.assertEqual(7, len(self.parse("nightfall_many_vuln.json")))

    def test_detections_may_be_indexed_by_violation_id(self):
        """
        Nightfall needs two calls per violation, and a detection carries no violation id.

        So an export either nests the detections on the violation - as the one-violation sample does -
        or keys them by violation id, which is what this sample does. Both have to work or the
        evidence, the credential verdict and the severity are all lost.
        """
        findings = self.by_uid("nightfall_many_vuln.json")
        github = findings["vio_github_public"]
        self.assertIn("redacted value `sk_live_****REDACTED****`", github.description)
        self.assertIn("redacted value `ghp_****REDACTED****`", github.description)
        self.assertEqual(7, github.line)

    def test_nested_and_indexed_detections_agree(self):
        with (get_unit_tests_scans_path("nightfall") / "nightfall_one_vuln.json").open(encoding="utf-8") as file:
            export = json.load(file)
        violation = export["violations"][0]
        detections = violation.pop("findings")

        indexed = self.parse_string({"violations": [violation], "findings": {violation["id"]: detections}})
        nested = self.parse("nightfall_one_vuln.json")
        self.assertEqual(nested[0].title, indexed[0].title)
        self.assertEqual(nested[0].severity, indexed[0].severity)
        self.assertEqual(nested[0].description, indexed[0].description)

    def test_a_verified_live_credential_is_always_critical(self):
        """
        A working secret outranks the policy's own risk label.

        Nightfall marks a key ACTIVE when it authenticated with it and SIGNATURE_VERIFIED when it
        verified the signature; either means the credential is live.
        """
        for status, expected in (("ACTIVE", "Critical"), ("SIGNATURE_VERIFIED", "Critical"),
                                 ("UNVERIFIED", "Low"), ("EXPIRED", "Low"), ("INVALID_SIGNATURE", "Low"),
                                 ("", "Low")):
            with self.subTest(status=status):
                findings = self.parse_string({"violations": [{
                    "id": "vio_1", "integration": "GITHUB", "risk": "LOW", "state": "ACTIVE",
                    "findings": [{"metadata": {"apiKeyMetaData": {"status": status, "kind": "AWS"}}}],
                }]})
                self.assertEqual(expected, findings[0].severity)

    def test_risk_labels(self):
        for risk, expected in (("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"),
                               ("LOW", "Low"), ("NO_RISK", "Info"), ("UNSPECIFIED", "Info"),
                               ("SEVERE", "Info"), ("", "Info")):
            with self.subTest(risk=risk):
                findings = self.parse_string({"violations": [
                    {"id": "vio_1", "integration": "SLACK", "risk": risk, "state": "ACTIVE"},
                ]})
                self.assertEqual(expected, findings[0].severity)

    def test_unrecognised_risk_label_is_info(self):
        """An unknown label is Info rather than a guess, and is kept as a tag so it is not lost."""
        finding = self.by_uid("nightfall_many_vuln.json")["vio_zendesk_unknown_risk"]
        self.assertEqual("Info", finding.severity)
        self.assertIn("SEVERE", finding.unsaved_tags)

    def test_violation_states(self):
        """
        A pending violation is open but not verified - nobody has triaged it yet.

        An expired one is out of scope: Nightfall can no longer see the resource, so it can neither
        confirm the data is gone nor that it is still there.
        """
        states = {
            "ACTIVE": (True, False, False, True),
            "PENDING": (True, False, False, False),
            "RESOLVED": (False, True, False, True),
            "EXPIRED": (False, False, True, True),
            "": (False, False, False, False),
        }
        for state, (active, mitigated, out_of_scope, verified) in states.items():
            with self.subTest(state=state):
                findings = self.parse_string({"violations": [
                    {"id": "vio_1", "integration": "SLACK", "risk": "LOW", "state": state},
                ]})
                self.assertEqual(active, findings[0].active)
                self.assertEqual(mitigated, findings[0].is_mitigated)
                self.assertEqual(out_of_scope, findings[0].out_of_scope)
                self.assertEqual(verified, findings[0].verified)

    def test_state_is_read_case_insensitively(self):
        findings = self.parse_string({"violations": [
            {"id": "vio_1", "integration": "SLACK", "risk": "LOW", "state": "resolved"},
        ]})
        self.assertTrue(findings[0].is_mitigated)
        self.assertFalse(findings[0].active)

    def test_location_per_integration(self):
        """
        Every integration nests its own metadata block and describes a location differently.

        This is the connector's Metadata.Location(), which is a table rather than a formula.
        """
        cases = (
            ({"slackMetadata": {"workspaceName": "Example Workspace", "location": "#general"}},
             "Example Workspace / #general"),
            ({"githubMetadata": {"organization": "example-org", "repository": "generic-app",
                                 "filePath": "app/main.py"}}, "example-org/generic-app:app/main.py"),
            ({"githubMetadata": {"organization": "example-org", "repository": "generic-app"}},
             "example-org/generic-app"),
            ({"gdriveMetadata": {"drive": "Shared drive", "fileName": "notes.docx"}},
             "Shared drive / notes.docx"),
            ({"jiraMetadata": {"projectName": "PLATFORM", "ticketNumber": "PLATFORM-1"}}, "PLATFORM PLATFORM-1"),
            ({"confluenceMetadata": {"spaceName": "Engineering", "itemName": "Runbook"}}, "Engineering / Runbook"),
            ({"salesforceMetadata": {"orgName": "Example", "objectName": "Account"}}, "Example / Account"),
            ({"zendeskMetadata": {"ticketTitle": "Cannot sign in", "ticketID": "4321"}}, "Cannot sign in #4321"),
            ({"zendeskMetadata": {"ticketTitle": "Cannot sign in", "ticketID": "REQ-1"}}, "Cannot sign in REQ-1"),
            ({"notionMetadata": {"workspaceName": "Example", "pageTitle": "Runbook"}}, "Example / Runbook"),
            ({"m365TeamsMetadata": {"teamName": "Platform", "channelName": "General"}}, "Platform / General"),
            ({"m365OnedriveMetadata": {"driveOwnerName": "example-user", "driveItemName": "notes.docx"}},
             "example-user / notes.docx"),
            ({"browserMetadata": {"browserName": "Chrome", "location": "https://app.example.com"}},
             "Chrome / https://app.example.com"),
            ({"inlineEmailMetadata": {"domain": "example.com", "subject": "Invoice"}}, "example.com / Invoice"),
            ({}, ""),
        )
        for metadata, expected in cases:
            with self.subTest(metadata=next(iter(metadata), "none")):
                self.assertEqual(expected, NightfallParser().location({"metadata": metadata}))

    def test_title_without_a_location_or_integration(self):
        """A violation with no metadata block names the integration but no location."""
        findings = self.parse_string({"violations": [
            {"id": "vio_1", "integration": "M365_TEAMS", "policyNames": ["Chat attachments"]},
        ]})
        self.assertEqual("Chat attachments exposed in M365 TEAMS", findings[0].title)

        findings = self.parse_string({"violations": [{"id": "vio_1", "policyNames": ["A policy"]}]})
        self.assertEqual("A policy exposed", findings[0].title)

    def test_title_falls_back_to_the_policy_then_to_a_generic_label(self):
        findings = self.by_uid("nightfall_many_vuln.json")
        self.assertEqual(
            "Payment card numbers in chat exposed in SLACK (Example Workspace / #general)",
            findings["vio_slack_pending"].title,
        )
        self.assertEqual(
            "Sensitive data exposed in JIRA (PLATFORM PLATFORM-1234)",
            findings["vio_jira_expired"].title,
        )

    def test_an_unspecified_credential_kind_is_named_api(self):
        """
        The credential still leads the title even when Nightfall cannot say what kind it is.

        A detection that identified *some* key is more specific than the policy name, so the
        connector prefers it and calls the kind "API".
        """
        finding = self.by_uid("nightfall_many_vuln.json")["vio_teams_no_metadata"]
        self.assertEqual("API credential exposed in M365 TEAMS", finding.title)
        self.assertIn("UNSPECIFIED key (EXPIRED)", finding.description)

    def test_integration_label_replaces_underscores(self):
        self.assertEqual("M365 TEAMS", NightfallParser().integration_label("M365_TEAMS"))
        self.assertEqual("SLACK", NightfallParser().integration_label("SLACK"))

    def test_exposure_notes(self):
        """Only three integrations report a sharing state that makes the exposure external."""
        findings = self.by_uid("nightfall_many_vuln.json")
        self.assertIn("**Exposure:** Drive permission ANYONE_WITH_LINK", findings["vio_gdrive_resolved"].description)
        self.assertIn("**Exposure:** the Notion page is shared externally", findings["vio_notion_shared"].description)
        self.assertIn("**Exposure:** the GitHub repository is public", findings["vio_github_public"].description)
        self.assertNotIn("**Exposure:**", findings["vio_jira_expired"].description)

    def test_absent_is_repo_private_reads_as_public(self):
        """
        Matching the connector: a repository Nightfall did not call private is treated as public.

        The alternative - staying quiet - would understate a violation that may well be world
        readable, which is the whole point of the note.
        """
        findings = self.parse_string({"violations": [{
            "id": "vio_1", "integration": "GITHUB", "risk": "LOW", "state": "ACTIVE",
            "metadata": {"githubMetadata": {"organization": "example-org", "repository": "generic-app"}},
        }]})
        self.assertIn("**Exposure:** the GitHub repository is public", findings[0].description)

    def test_references_are_deduplicated(self):
        findings = self.parse_string({"violations": [{
            "id": "vio_1", "integration": "GDRIVE", "risk": "LOW", "state": "ACTIVE",
            "resourceLink": "https://drive.example.com/file/d/1",
            "metadata": {"gdriveMetadata": {"fileLink": "https://drive.example.com/file/d/1"}},
            "fileDetails": {"permalink": "https://drive.example.com/file/d/1/view"},
        }]})
        self.assertEqual(
            "https://drive.example.com/file/d/1\nhttps://drive.example.com/file/d/1/view",
            findings[0].references,
        )

    def test_integrations_without_a_link_field_have_no_references(self):
        """Zendesk, browser and inline-email violations carry no permalink in the connector."""
        finding = self.by_uid("nightfall_many_vuln.json")["vio_zendesk_unknown_risk"]
        self.assertEqual("", finding.references)

    def test_file_path_and_line_are_github_only(self):
        """
        Only a GitHub violation has a code location.

        A Slack message or a Drive file has no path in a repository, so file_path stays unset rather
        than being filled with something that is not a path.
        """
        findings = self.by_uid("nightfall_many_vuln.json")
        self.assertEqual("config/local.env", findings["vio_github_public"].file_path)
        self.assertFalse(findings["vio_slack_pending"].file_path)
        self.assertFalse(findings["vio_gdrive_resolved"].file_path)
        self.assertIsNone(findings["vio_slack_pending"].line)

    def test_line_comes_from_the_first_detection_that_has_one(self):
        findings = self.parse_string({"violations": [{
            "id": "vio_1", "integration": "GITHUB", "risk": "LOW", "state": "ACTIVE",
            "findings": [
                {"redactedSensitiveText": "****"},
                {"redactedLocation": {"lineRange": {"start": 0, "end": 0}}},
                {"redactedLocation": {"lineRange": {"start": 19, "end": 19}}},
            ],
        }]})
        self.assertEqual(19, findings[0].line)

    def test_detection_location_prefers_the_sub_location(self):
        finding = self.by_uid("nightfall_many_vuln.json")["vio_slack_pending"]
        self.assertIn("confidence LIKELY, message body", finding.description)
        self.assertNotIn("line ", finding.description)

    def test_only_redacted_detection_text_is_imported(self):
        """
        Nightfall's API only ever returns redacted detection text.

        This parser reads that field and no other, so a sensitive value cannot reach a finding even
        if a hand-edited export carried one.
        """
        findings = self.parse_string({"violations": [{
            "id": "vio_1", "integration": "GITHUB", "risk": "LOW", "state": "ACTIVE",
            "findings": [{
                "redactedSensitiveText": "AKIA****REDACTED****",
                "sensitiveText": "a value no Nightfall response contains",
                "redactedContext": {"beforeContext": 'KEY = "', "afterContext": '"'},
            }],
        }]})
        self.assertIn("AKIA****REDACTED****", findings[0].description)
        self.assertNotIn("a value no Nightfall response contains", findings[0].description)
        self.assertNotIn("KEY = ", findings[0].description)

    def test_severity_justification_only_when_scored(self):
        for score, expected in ((8.5, "Nightfall risk score: 8.5 (source: POLICY)"),
                                (9.0, "Nightfall risk score: 9 (source: POLICY)"),
                                (5, "Nightfall risk score: 5 (source: POLICY)"),
                                (0, None), (None, None)):
            with self.subTest(score=score):
                violation = {"id": "vio_1", "integration": "SLACK", "risk": "LOW", "state": "ACTIVE",
                             "riskSource": "POLICY"}
                if score is not None:
                    violation["riskScore"] = score
                findings = self.parse_string({"violations": [violation]})
                self.assertEqual(expected, findings[0].severity_justification)

    def test_severity_justification_without_a_source(self):
        findings = self.parse_string({"violations": [
            {"id": "vio_1", "integration": "SLACK", "risk": "LOW", "state": "ACTIVE", "riskScore": 4.25},
        ]})
        self.assertEqual("Nightfall risk score: 4.25", findings[0].severity_justification)

    def test_date_is_the_violations_creation_time(self):
        findings = self.by_uid("nightfall_many_vuln.json")
        self.assertEqual(datetime(2024, 6, 1, tzinfo=UTC).date(), findings["vio_slack_pending"].date)
        self.assertEqual(datetime(2024, 7, 15, tzinfo=UTC).date(), findings["vio_github_public"].date)

    def test_missing_creation_time_is_today(self):
        """Nightfall sends the creation time as unix seconds; zero means it sent none."""
        finding = self.by_uid("nightfall_many_vuln.json")["vio_notion_shared"]
        self.assertEqual(datetime.now(tz=UTC).date(), finding.date)

    def test_policies_are_listed_and_the_first_is_the_rule_id(self):
        finding = self.by_uid("nightfall_many_vuln.json")["vio_slack_pending"]
        self.assertIn("**Policies:** Payment card numbers in chat, PII in chat", finding.description)
        self.assertEqual("Payment card numbers in chat", finding.vuln_id_from_tool)

    def test_no_policies_leaves_the_rule_id_unset(self):
        finding = self.by_uid("nightfall_many_vuln.json")["vio_jira_expired"]
        self.assertIsNone(finding.vuln_id_from_tool)

    def test_credential_kinds_become_tags(self):
        finding = self.by_uid("nightfall_many_vuln.json")["vio_github_public"]
        # GITHUB is already there as the integration, so the GitHub-token kind is not repeated.
        self.assertEqual(["dlp", "GITHUB", "LOW", "STRIPE"], finding.unsaved_tags)

    def test_a_bare_list_of_violations_is_accepted(self):
        findings = self.parse_string([{"id": "vio_1", "integration": "SLACK", "risk": "HIGH", "state": "ACTIVE"}])
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("Nightfall", str(context.exception))

    def test_export_without_a_violation_list_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("violations", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"violations": [
            "not an object",
            None,
            {"id": "vio_1", "integration": "SLACK", "risk": "HIGH", "state": "ACTIVE"},
        ]})
        self.assertEqual(1, len(findings))

    def test_malformed_detections_are_skipped(self):
        findings = self.parse_string({"violations": [{
            "id": "vio_1", "integration": "GITHUB", "risk": "LOW", "state": "ACTIVE",
            "findings": ["not an object", None, {"confidence": "LIKELY"}],
        }]})
        self.assertEqual(1, len(findings))
        self.assertIn("- confidence LIKELY", findings[0].description)

    def test_severity_is_always_a_known_value(self):
        for filename in ("nightfall_many_vuln.json", "nightfall_one_vuln.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
