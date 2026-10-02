import io

from dojo.models import Finding, Test
from dojo.tools.lynis.parser import LynisParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestLynisParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("lynis") / filename).open(encoding="utf-8") as file:
            return list(LynisParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = LynisParser()
        self.assertEqual(["Lynis Scan"], parser.get_scan_types())
        self.assertEqual("Lynis Scan", parser.get_label_for_scan_types("Lynis Scan"))
        self.assertIn("lynis audit system", parser.get_description_for_scan_types("Lynis Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("lynis_no_vuln.dat")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("lynis_one_vuln.dat")))

    def test_one_vuln_field_mapping(self):
        """
        Full field mapping, from a real `lynis audit system --tests "BOOT-5104"` run.

        The single result is Lynis's own self-update suggestion, which fires on every run and is
        therefore the floor for any Lynis report.
        """
        findings = self.parse("lynis_one_vuln.dat")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("LYNIS", finding.vuln_id_from_tool)
        self.assertIn("This release is more than 4 months old", finding.title)
        self.assertEqual("Low", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)

        self.assertIn("**Test ID:** LYNIS", finding.description)
        self.assertIn("**Result:** suggestion", finding.description)

    def test_a_host_audit_is_a_dynamic_finding_with_no_source_position(self):
        """
        Lynis inspects the state of a running machine rather than reading source.

        So there is no file or line, and the finding is dynamic rather than static - the opposite of
        every other parser in this branch.
        """
        finding = self.parse("lynis_one_vuln.dat")[0]
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertIsNone(getattr(finding, "file_path", None))
        self.assertIsNone(getattr(finding, "line", None))

    def test_host_context_is_attached(self):
        """
        Nothing in an individual result says which machine it came from.

        A Lynis report describes exactly one host, so the header's identity keys are copied onto
        every finding - otherwise two hosts' findings would be indistinguishable after import.
        """
        finding = self.parse("lynis_one_vuln.dat")[0]
        self.assertIn("**Operating system:** Debian GNU/Linux 13 (trixie)", finding.description)
        self.assertIn("**Lynis version:** 3.1.4", finding.description)
        self.assertIn("**Hostname:**", finding.description)
        self.assertIn("**Hardening index:**", finding.description)

    def test_many_vuln(self):
        findings = self.parse("lynis_many_vuln.dat")
        self.assertEqual(38, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertTrue(finding.dynamic_finding)
            self.assertTrue(finding.vuln_id_from_tool)

    def test_warnings_and_suggestions_are_different_severities(self):
        """
        Which repeated key a result used is the only severity signal Lynis gives.

        A warning is something Lynis believes is wrong; a suggestion is hardening advice. The full
        audit has one warning and thirty-seven suggestions.
        """
        findings = self.parse("lynis_many_vuln.dat")
        warnings = [f for f in findings if f.severity == "Medium"]
        suggestions = [f for f in findings if f.severity == "Low"]
        self.assertEqual(1, len(warnings))
        self.assertEqual(37, len(suggestions))

        self.assertEqual("LOGG-2138", warnings[0].vuln_id_from_tool)
        self.assertIn("klogd is not running", warnings[0].title)
        self.assertIn("**Result:** warning", warnings[0].description)

    def test_many_vuln_test_ids(self):
        findings = self.parse("lynis_many_vuln.dat")
        ids = {finding.vuln_id_from_tool for finding in findings}
        for expected in ("LOGG-2138", "DEB-0280", "DEB-0810", "LYNIS"):
            self.assertIn(expected, ids)

    def test_pipe_delimited_fields(self):
        """Test id, text, details and solution are pipe-separated, with a bare "-" for empty."""
        report = io.StringIO(
            "os_fullname=Debian GNU/Linux 13\n"
            "warning[]=KRNL-5820|Reboot of system is most likely needed|details here|"
            "Reboot the system|\n",
        )
        finding = list(LynisParser().get_findings(report, Test()))[0]
        self.assertEqual("KRNL-5820", finding.vuln_id_from_tool)
        self.assertEqual("Reboot of system is most likely needed", finding.title)
        self.assertEqual("Reboot the system", finding.mitigation)
        self.assertIn("**Details:** details here", finding.description)

    def test_dash_means_empty(self):
        report = io.StringIO("suggestion[]=BOOT-5122|Set a password on GRUB|-|-|\n")
        finding = list(LynisParser().get_findings(report, Test()))[0]
        self.assertEqual("Set a password on GRUB", finding.title)
        self.assertIsNone(finding.mitigation)
        self.assertNotIn("**Details:**", finding.description)

    def test_text_containing_a_pipe_is_kept_intact(self):
        """A test's text is free to contain the delimiter, so the split cannot be naive."""
        report = io.StringIO("warning[]=TEST-0001|check a|b in the text|-|-|\n")
        finding = list(LynisParser().get_findings(report, Test()))[0]
        self.assertEqual("TEST-0001", finding.vuln_id_from_tool)
        self.assertEqual("check a|b in the text", finding.title)

    def test_lines_without_a_separator_are_ignored(self):
        report = io.StringIO("# a comment\n\nsuggestion[]=X-1|text|-|-|\nnot a key value line\n")
        self.assertEqual(1, len(list(LynisParser().get_findings(report, Test()))))

    def test_bytes_input(self):
        report = io.BytesIO(b"suggestion[]=X-1|text|-|-|\n")
        findings = list(LynisParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("text", findings[0].title)

    def test_empty_report(self):
        self.assertEqual([], list(LynisParser().get_findings(io.StringIO(""), Test())))

    def test_result_with_only_a_test_id(self):
        report = io.StringIO("warning[]=ONLY-ID|-|-|-|\n")
        finding = list(LynisParser().get_findings(report, Test()))[0]
        self.assertEqual("ONLY-ID", finding.title)
        self.assertEqual("ONLY-ID", finding.vuln_id_from_tool)
