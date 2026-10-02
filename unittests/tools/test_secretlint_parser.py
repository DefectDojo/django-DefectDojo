import io
import json

from dojo.models import Finding, Test
from dojo.tools.secretlint.parser import SecretlintParser, short_rule_name
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestSecretlintParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("secretlint") / filename).open(encoding="utf-8") as file:
            return list(SecretlintParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("secretlint") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = SecretlintParser()
        self.assertEqual(["Secretlint Scan"], parser.get_scan_types())
        self.assertEqual("Secretlint Scan", parser.get_label_for_scan_types("Secretlint Scan"))
        # Masking is the behaviour a user has to know about, because --no-maskSecrets puts the raw
        # secret into the report and therefore into the finding.
        self.assertIn("maskSecrets", parser.get_description_for_scan_types("Secretlint Scan"))

    def test_short_rule_name(self):
        """Rule ids shorten for readability, and unfamiliar shapes are left alone."""
        self.assertEqual("aws", short_rule_name("@secretlint/secretlint-rule-aws"))
        self.assertEqual("npm", short_rule_name("secretlint-rule-npm"))
        self.assertEqual("internal", short_rule_name("@company/secretlint-rule-internal"))
        # A third-party rule that does not use the secretlint-rule- convention keeps its name
        # rather than being mangled into something that no longer identifies it.
        self.assertEqual("my-own-rule", short_rule_name("@company/my-own-rule"))
        self.assertEqual("@secretlint/secretlint-rule-", short_rule_name("@secretlint/secretlint-rule-"))

    def test_no_vuln(self):
        """
        A clean scan is not an empty report.

        secretlint lists every file it read and leaves "messages" empty, so the parser has to
        return nothing for an entry that is present but reported no secrets.
        """
        report = self.report("secretlint_no_vuln.json")
        self.assertEqual(1, len(report), "the clean report still lists the scanned file")
        self.assertEqual([], report[0]["messages"])
        self.assertEqual(0, len(self.parse("secretlint_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("secretlint_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `secretlint --format json` run."""
        findings = self.parse("secretlint_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Hard coded AWSSecretAccessKey found in aws-config.ini", finding.title)
        self.assertEqual("aws/AWSSecretAccessKey", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(798, finding.cwe)
        self.assertEqual("/src/generic-app/aws-config.ini", finding.file_path)
        self.assertEqual(3, finding.line)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(1, finding.nb_occurences)

        self.assertIn("**Rule:** @secretlint/secretlint-rule-aws", finding.description)
        self.assertIn("**Message ID:** AWSSecretAccessKey", finding.description)
        self.assertIn("**Line:** 3, column 0", finding.description)
        self.assertIn("secretlint-rule-aws/README.md#AWSSecretAccessKey", finding.description)

    def test_title_uses_base_name_not_the_absolute_path(self):
        """
        Secretlint always reports an absolute path.

        Putting it in the title would tie every finding to one checkout location, so the title
        carries the base name while file_path keeps what the tool actually said.
        """
        finding = self.parse("secretlint_one_vuln.json")[0]
        self.assertNotIn("/src/generic-app", finding.title)
        self.assertTrue(finding.file_path.startswith("/src/generic-app/"))

    def test_many_vuln(self):
        findings = self.parse("secretlint_many_vuln.json")
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual(798, finding.cwe)
            self.assertTrue(finding.static_finding)

    def test_many_vuln_rules_and_lines(self):
        """Each rule family keeps its own identifier, file and line."""
        findings = self.parse("secretlint_many_vuln.json")
        located = sorted(
            (finding.vuln_id_from_tool, finding.file_path.rsplit("/", 1)[-1], finding.line)
            for finding in findings
        )
        self.assertEqual(
            [
                ("aws/AWSSecretAccessKey", "aws-config.ini", 3),
                ("aws/AWSSecretAccessKey", "deploy.env", 2),
                ("github/GITHUB_TOKEN", "ci.env", 2),
                ("github/GITHUB_TOKEN", "deploy.env", 3),
            ],
            located,
        )

    def test_many_vuln_two_secrets_in_one_file(self):
        """One file entry can carry several messages, and each becomes its own finding."""
        findings = self.parse("secretlint_many_vuln.json")
        in_deploy = [f for f in findings if f.file_path.endswith("deploy.env")]
        self.assertEqual(2, len(in_deploy))
        self.assertEqual({2, 3}, {finding.line for finding in in_deploy})
        self.assertEqual(
            {"aws/AWSSecretAccessKey", "github/GITHUB_TOKEN"},
            {finding.vuln_id_from_tool for finding in in_deploy},
        )

    def test_many_vuln_ignores_the_file_with_no_secrets(self):
        """The report lists a clean file alongside the dirty ones; it must contribute nothing."""
        report = self.report("secretlint_many_vuln.json")
        clean = [entry for entry in report if not entry["messages"]]
        self.assertEqual(1, len(clean), "the fixture is meant to contain one clean file")
        clean_name = clean[0]["filePath"]

        findings = self.parse("secretlint_many_vuln.json")
        self.assertNotIn(clean_name, [finding.file_path for finding in findings])

    def test_description_never_contains_the_scanned_file(self):
        """
        A secretlint report embeds the whole content of every scanned file under sourceContent,
        secrets included and unmasked. None of it may reach the finding, or importing a report
        would republish the source of every scanned file into DefectDojo.
        """
        report = self.report("secretlint_many_vuln.json")
        sources = [entry["sourceContent"] for entry in report if entry.get("sourceContent")]
        self.assertEqual(4, len(sources), "the fixture is meant to carry sourceContent to test against")

        findings = self.parse("secretlint_many_vuln.json")
        for source in sources:
            for source_line in source.splitlines():
                if not source_line.strip():
                    continue
                for finding in findings:
                    self.assertNotIn(source_line.strip(), finding.description)

    def test_severity_map(self):
        """Secretlint's info/warning/error levels each land on a distinct DefectDojo severity."""
        parser = SecretlintParser()
        for level, expected in [("error", "High"), ("warning", "Medium"), ("info", "Info")]:
            findings = list(parser.get_findings(self.report_with_severity(level), Test()))
            self.assertEqual(1, len(findings))
            self.assertEqual(expected, findings[0].severity)

        # An unrecognised level is reported rather than dropped, and errs on the loud side.
        findings = list(parser.get_findings(self.report_with_severity("something-new"), Test()))
        self.assertEqual("High", findings[0].severity)

    def report_with_severity(self, severity):
        return io.StringIO(json.dumps([{
            "filePath": "/src/generic-app/config.env",
            "sourceContent": "TOKEN=redacted\n",
            "sourceContentType": "text",
            "messages": [{
                "ruleId": "@secretlint/secretlint-rule-aws",
                "messageId": "AWSSecretAccessKey",
                "message": "found AWS Secret Access Key: ****",
                "severity": severity,
                "loc": {"start": {"line": 1, "column": 6}, "end": {"line": 1, "column": 14}},
            }],
        }]))

    def test_repeated_message_collapses_into_one_finding(self):
        """The same rule firing twice at one place is one defect with two occurrences."""
        message = {
            "ruleId": "@secretlint/secretlint-rule-aws",
            "messageId": "AWSSecretAccessKey",
            "message": "found AWS Secret Access Key: ****",
            "severity": "error",
            "loc": {"start": {"line": 1, "column": 6}, "end": {"line": 1, "column": 14}},
        }
        report = io.StringIO(json.dumps([{
            "filePath": "/src/generic-app/config.env",
            "messages": [message, dict(message)],
        }]))
        findings = list(SecretlintParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual(2, findings[0].nb_occurences)

    def test_empty_report(self):
        self.assertEqual([], list(SecretlintParser().get_findings(io.StringIO("[]"), Test())))
        self.assertEqual([], list(SecretlintParser().get_findings(io.StringIO("null"), Test())))

    def test_wrong_shape_is_rejected(self):
        """
        A JSON object is a different formatter's output, not a --format json report.

        TypeError matches the AWS Security Hub, AWS Inspector2, AnchoreCTL Policies and GitHub SAST
        parsers, which all reject a wrong-shaped document the same way.
        """
        with self.assertRaises(TypeError):
            list(SecretlintParser().get_findings(io.StringIO('{"results": []}'), Test()))
        with self.assertRaises(TypeError):
            list(SecretlintParser().get_findings(io.StringIO("[1, 2]"), Test()))

    def test_message_without_a_rule_still_imports(self):
        """A custom rule need not supply every field; the finding degrades rather than crashing."""
        report = io.StringIO(json.dumps([{
            "filePath": "/src/generic-app/config.env",
            "messages": [{"message": "found something", "severity": "error"}],
        }]))
        findings = list(SecretlintParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("Hard coded secret found in config.env", findings[0].title)
        self.assertIsNone(findings[0].vuln_id_from_tool)
        self.assertIsNone(findings[0].line)

    def test_only_detections_become_findings(self):
        """
        Secretlint's filter rules describe ranges to ignore, not secrets that were found.

        A suppressed detection is absent from the report today, so this is a guard rather than a
        fix: if a future formatter includes non-detection entries, they must not import as secrets
        named after the filter that produced them.
        """
        report = io.StringIO(json.dumps([{
            "filePath": "/src/generic-app/config.env",
            "messages": [
                {
                    "type": "ignore",
                    "ruleId": "@secretlint/secretlint-rule-filter-comments",
                    "messageId": "IGNORE_MESSAGE",
                    "message": "ignored by secretlint-disable",
                    "severity": "info",
                },
                {
                    "type": "message",
                    "ruleId": "@secretlint/secretlint-rule-aws",
                    "messageId": "AWSSecretAccessKey",
                    "message": "found AWS Secret Access Key: ****",
                    "severity": "error",
                    "loc": {"start": {"line": 1, "column": 6}, "end": {"line": 1, "column": 14}},
                },
            ],
        }]))
        findings = list(SecretlintParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("aws/AWSSecretAccessKey", findings[0].vuln_id_from_tool)

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("secretlint_one_vuln.json")
        self.assertEqual(1, len(findings))
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("/src/generic-app/aws-config.ini", locations[0].data["file_path"])
        self.assertEqual(3, locations[0].data["line"])
