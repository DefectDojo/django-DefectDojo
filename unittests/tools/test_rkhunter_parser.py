import io

from dojo.models import Finding, Test
from dojo.tools.rkhunter.parser import RkhunterParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRkhunterParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("rkhunter") / filename).open(encoding="utf-8") as file:
            return list(RkhunterParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = RkhunterParser()
        self.assertEqual(["rkhunter Scan"], parser.get_scan_types())
        self.assertEqual("rkhunter Scan", parser.get_label_for_scan_types("rkhunter Scan"))
        self.assertIn("rkhunter --check", parser.get_description_for_scan_types("rkhunter Scan"))

    def test_no_vuln(self):
        """
        A clean rkhunter log is over a thousand lines and contains no findings.

        Almost every line is a passing check, so file size says nothing about whether anything was
        flagged.
        """
        self.assertEqual(0, len(self.parse("rkhunter_no_vuln.log")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("rkhunter_one_vuln.log")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `rkhunter --check --enable system_configs` run."""
        findings = self.parse("rkhunter_one_vuln.log")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Checking for a running system logging daemon", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)

        self.assertIn("**Check:** Checking for a running system logging daemon", finding.description)
        self.assertIn("**Warning:** No running system logging daemon has been found.",
                      finding.description)

    def test_only_the_warning_result_becomes_a_finding(self):
        """
        Rkhunter marks every check with a bracketed outcome, and most of them pass.

        The clean log has over a thousand "Not found" and "OK" results; only "[ Warning ]" is a
        finding, so a parser matching brackets loosely would import the entire log.
        """
        with (get_unit_tests_scans_path("rkhunter") / "rkhunter_many_vuln.log").open(
            encoding="utf-8",
        ) as file:
            content = file.read()
        self.assertGreater(content.count("[ Not found ]"), 100)
        self.assertGreater(content.count("[ OK ]"), 100)
        self.assertEqual(4, len(self.parse("rkhunter_many_vuln.log")))

    def test_a_host_audit_is_dynamic_with_no_source_position(self):
        finding = self.parse("rkhunter_one_vuln.log")[0]
        self.assertTrue(finding.dynamic_finding)
        self.assertIsNone(getattr(finding, "file_path", None))
        self.assertIsNone(getattr(finding, "line", None))

    def test_host_context_is_attached(self):
        """A log describes one machine, and nothing in an individual check identifies it."""
        finding = self.parse("rkhunter_one_vuln.log")[0]
        self.assertIn("**Rootkit Hunter version:** 1.4.6", finding.description)
        self.assertIn("**Operating system:** Debian GNU/Linux 13 (trixie)", finding.description)
        self.assertIn("**Host:**", finding.description)

    def test_many_vuln(self):
        findings = self.parse("rkhunter_many_vuln.log")
        self.assertEqual(4, len(findings))
        self.assertEqual(
            [
                "Checking for a running system logging daemon",
                "Checking hard link count on '/sbin/init'",
                "Checking kernel module names",
                "Suckit Rootkit additional checks",
            ],
            sorted(finding.title for finding in findings),
        )

    def test_a_flagged_check_without_an_explanation_says_so(self):
        """
        Not every flagged check has a Warning: line - two of the four in a default run do not.

        Saying so beats leaving the reader wondering whether the parser lost something.
        """
        findings = self.parse("rkhunter_many_vuln.log")
        bare = next(f for f in findings if f.title == "Checking hard link count on '/sbin/init'")
        self.assertIn("without an explanatory message", bare.description)

    def test_a_result_line_that_is_its_own_warning(self):
        """
        One line in a default run is both a result and its own warning.

        "Warning: Suckit Rootkit additional checks [ Warning ]" would otherwise keep the prefix in
        the title.
        """
        findings = self.parse("rkhunter_many_vuln.log")
        titles = [finding.title for finding in findings]
        self.assertIn("Suckit Rootkit additional checks", titles)
        self.assertNotIn("Warning: Suckit Rootkit additional checks", titles)

    def test_interleaved_info_lines_are_not_glued_onto_a_warning(self):
        """
        Rkhunter writes Info: lines between warnings.

        Treating any following line as a continuation would put unrelated text inside the finding,
        which is what happened before the prefix check was added.
        """
        report = io.StringIO(
            "[00:00:01] Checking something                    [ Warning ]\n"
            "[00:00:01] Warning: the real problem.\n"
            "[00:00:01] Info: unrelated detail about the run.\n"
            "[00:00:02] Checking something else               [ OK ]\n",
        )
        finding = list(RkhunterParser().get_findings(report, Test()))[0]
        self.assertIn("**Warning:** the real problem.", finding.description)
        self.assertNotIn("unrelated detail", finding.description)

    def test_indented_continuation_is_joined(self):
        report = io.StringIO(
            "[00:00:01] Checking something                    [ Warning ]\n"
            "[00:00:01] Warning: first part\n"
            "[00:00:01]          second part\n"
            "[00:00:02] Checking something else               [ OK ]\n",
        )
        finding = list(RkhunterParser().get_findings(report, Test()))[0]
        self.assertIn("**Warning:** first part second part", finding.description)

    def test_several_warnings_for_one_check(self):
        report = io.StringIO(
            "[00:00:01] Checking something                    [ Warning ]\n"
            "[00:00:01] Warning: first problem\n"
            "[00:00:01] Warning: second problem\n"
            "[00:00:02] Checking something else               [ OK ]\n",
        )
        finding = list(RkhunterParser().get_findings(report, Test()))[0]
        self.assertIn("**Warning:** first problem", finding.description)
        self.assertIn("**Warning:** second problem", finding.description)

    def test_bytes_input(self):
        report = io.BytesIO(b"[00:00:01] Checking something                    [ Warning ]\n")
        findings = list(RkhunterParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("Checking something", findings[0].title)

    def test_empty_report(self):
        self.assertEqual([], list(RkhunterParser().get_findings(io.StringIO(""), Test())))

    def test_log_without_timestamps(self):
        """The timestamp prefix is stripped when present and its absence is not fatal."""
        report = io.StringIO("Checking something                    [ Warning ]\n")
        findings = list(RkhunterParser().get_findings(report, Test()))
        self.assertEqual("Checking something", findings[0].title)
