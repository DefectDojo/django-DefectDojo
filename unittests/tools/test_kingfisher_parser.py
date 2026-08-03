import io
import json
import re

from dojo.models import Finding, Test
from dojo.tools.kingfisher.parser import KingfisherParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKingfisherParser(DojoTestCase):
    def scan(self, filename):
        return get_unit_tests_scans_path("kingfisher") / filename

    def parse(self, filename):
        with self.scan(filename).open(encoding="utf-8") as file:
            return list(KingfisherParser().get_findings(file, Test()))

    def by_rule(self, filename):
        return {f.vuln_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_metadata(self):
        parser = KingfisherParser()
        self.assertEqual(["Kingfisher Scan"], parser.get_scan_types())
        self.assertEqual("Kingfisher Scan", parser.get_label_for_scan_types("Kingfisher Scan"))
        self.assertIn("not imported", parser.get_description_for_scan_types("Kingfisher Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("kingfisher_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("kingfisher_one_vuln.json")))

    def test_the_json_format_is_two_concatenated_documents(self):
        """
        `--format json` writes the findings document and then a run summary document.

        json.load() raises "Extra data" on that, so a parser that used it would reject every real
        Kingfisher report. Asserted against the fixture so the quirk stays documented.
        """
        raw = self.scan("kingfisher_one_vuln.json").read_text(encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError) as raised:
            json.loads(raw)
        self.assertIn("Extra data", raised.exception.msg)

        # The parser walks the stream instead, and the trailing summary yields no findings.
        self.assertEqual(1, len(self.parse("kingfisher_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        findings = self.parse("kingfisher_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Generic API Key found in deploy.env", finding.title)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("/scan/deploy.env", finding.file_path)
        self.assertEqual(2, finding.line)
        self.assertEqual(798, finding.cwe)
        self.assertEqual("kingfisher.generic.2", finding.vuln_id_from_tool)
        self.assertEqual("9651124012441020779", finding.unique_id_from_tool)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Rule:** Generic API Key", finding.description)
        self.assertIn("**Rule ID:** kingfisher.generic.2", finding.description)
        self.assertIn("**Location:** /scan/deploy.env:2:15", finding.description)
        self.assertIn("**Entropy:** 4.89", finding.description)

    def test_the_secret_is_never_copied_into_the_finding(self):
        """
        Kingfisher reports the matched secret; this parser must not carry it into DefectDojo.

        Path, line and column are enough to locate it, and copying the credential would duplicate a
        live secret into the database. The snippet is present in the report, so this asserts against
        the fixture's own value rather than a hypothetical one.
        """
        raw = self.scan("kingfisher_one_vuln.json").read_text(encoding="utf-8")
        snippet = json.JSONDecoder().raw_decode(raw.lstrip())[0]["findings"][0]["finding"]["snippet"]
        self.assertTrue(snippet)

        finding = self.parse("kingfisher_one_vuln.json")[0]
        for field in (finding.title, finding.description, str(finding.unsaved_tags)):
            self.assertNotIn(snippet, field)
        self.assertIn("not copied into this finding", finding.description)

    def test_many_vuln(self):
        findings = self.parse("kingfisher_many_vuln.json")
        self.assertEqual(5, len(findings))
        self.assertEqual(
            ["kingfisher.aws.1", "kingfisher.generic.2", "kingfisher.github.1",
             "kingfisher.pem.1", "kingfisher.slack.1"],
            sorted(f.vuln_id_from_tool for f in findings),
        )
        # Every finding is a credential exposure, so every one carries CWE-798.
        self.assertEqual({798}, {f.cwe for f in findings})

    def test_a_validated_live_credential_outranks_confidence(self):
        """
        A credential Kingfisher confirmed works is the strongest signal a secret scanner gives.

        Kingfisher emits no severity field, so this mapping is the parser's. Validation status wins
        over confidence: an Active credential is Critical whatever the confidence said.
        """
        findings = self.by_rule("kingfisher_many_vuln.json")
        active = findings["kingfisher.aws.1"]
        # High confidence in the fixture too, so this also proves validation is what decided it.
        self.assertIn("confidence:high", active.unsaved_tags)
        self.assertEqual("Critical", active.severity)
        self.assertIn("validation:active", active.unsaved_tags)
        self.assertIn("**Validation:** Active", active.description)

    def test_a_rejected_credential_is_low_not_info(self):
        """
        Kingfisher reached the provider and the credential was rejected.

        It is still committed in the source and still needs purging from history, so it stays a real
        finding. Info would mark it non-actionable.
        """
        finding = self.by_rule("kingfisher_many_vuln.json")["kingfisher.github.1"]
        self.assertEqual("Low", finding.severity)
        self.assertIn("validation:inactive", finding.unsaved_tags)

    def test_severity_falls_back_to_confidence_when_validation_says_nothing(self):
        findings = self.by_rule("kingfisher_many_vuln.json")
        # "Unknown" validation, medium confidence.
        self.assertEqual("Medium", findings["kingfisher.slack.1"].severity)
        # "Not Attempted" validation (i.e. --no-validate), low confidence.
        self.assertEqual("Low", findings["kingfisher.pem.1"].severity)
        self.assertEqual("Low", findings["kingfisher.generic.2"].severity)

    def test_the_severity_mapping_directly(self):
        parser = KingfisherParser()
        self.assertEqual("Critical", parser.severity("low", "Active"))
        self.assertEqual("Critical", parser.severity("", "active"))
        self.assertEqual("Low", parser.severity("high", "Inactive"))
        self.assertEqual("High", parser.severity("high", "Not Attempted"))
        self.assertEqual("Medium", parser.severity("medium", "Unknown"))
        self.assertEqual("Low", parser.severity("low", ""))
        # Neither signal recognised: Medium, never Info - these are all credential exposures.
        self.assertEqual("Medium", parser.severity("", ""))
        self.assertEqual("Medium", parser.severity("not-a-level", "not-a-status"))

    def test_the_jsonl_format_is_accepted_and_its_summary_line_skipped(self):
        """
        `--format jsonl` writes one finding per line, then the run summary as a final line.

        That summary line carries a "findings" key too, but as an integer count, so a parser that
        keyed off the key name alone would emit a bogus finding for it.
        """
        findings = self.parse("kingfisher_findings.jsonl")
        self.assertEqual(3, len(findings))
        self.assertEqual({798}, {f.cwe for f in findings})

        lines = [ln for ln in self.scan("kingfisher_findings.jsonl").read_text(
            encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(4, len(lines))
        summary = json.loads(lines[-1])
        self.assertIsInstance(summary["findings"], int)

    def test_a_finding_without_a_path_still_gets_a_title(self):
        report = io.StringIO(json.dumps({"findings": [{
            "rule": {"name": "Generic API Key", "id": "kingfisher.generic.2"},
            "finding": {"confidence": "high", "fingerprint": "1", "validation": {"status": ""}},
        }]}))
        finding = list(KingfisherParser().get_findings(report, Test()))[0]
        self.assertEqual("Generic API Key", finding.title)
        self.assertIsNone(finding.file_path)
        self.assertEqual("High", finding.severity)

    def test_a_bare_findings_document_is_accepted(self):
        report = io.StringIO(json.dumps({"findings": [{
            "rule": {"name": "AWS Access Key ID", "id": "kingfisher.aws.1"},
            "finding": {"path": "a/b/config.yml", "line": 3, "confidence": "high",
                        "fingerprint": "f1", "validation": {"status": "Active"}},
        }]}))
        finding = list(KingfisherParser().get_findings(report, Test()))[0]
        self.assertEqual("AWS Access Key ID found in config.yml", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(KingfisherParser().get_findings(io.StringIO("not json at all"), Test()))
        self.assertIn("Kingfisher report", str(raised.exception))

    def test_the_fixtures_carry_only_marked_fake_secrets(self):
        """
        These fixtures live in a public repository.

        Every secret value in them is a marked fake. This asserts it rather than trusting it, since
        a future fixture refresh could paste in real scan output.
        """
        for name in ("kingfisher_one_vuln.json", "kingfisher_many_vuln.json",
                     "kingfisher_findings.jsonl"):
            text = self.scan(name).read_text(encoding="utf-8")
            for snippet in re.findall(r'"snippet":\s*"([^"]*)"', text):
                self.assertRegex(
                    snippet, r"(?i)fake|example",
                    msg=f"{name} has an unmarked secret value: {snippet!r}",
                )
