import io

from dojo.models import Finding, Test
from dojo.tools.chkrootkit.parser import ChkrootkitParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestChkrootkitParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("chkrootkit") / filename).open(encoding="utf-8") as file:
            return list(ChkrootkitParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = ChkrootkitParser()
        self.assertEqual(["chkrootkit Scan"], parser.get_scan_types())
        self.assertEqual("chkrootkit Scan", parser.get_label_for_scan_types("chkrootkit Scan"))
        self.assertIn("chkrootkit", parser.get_description_for_scan_types("chkrootkit Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("chkrootkit_no_vuln.txt")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("chkrootkit_one_vuln.txt")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `chkrootkit lkm` run."""
        findings = self.parse("chkrootkit_one_vuln.txt")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "Searching for for hidden directories using chkdirs: WARNING", finding.title,
        )
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertIsNone(getattr(finding, "file_path", None))

        self.assertIn("**Verdict:** WARNING", finding.description)
        self.assertIn("Possible LKM Trojan installed", finding.description)

    def test_explanations_attach_to_the_check_that_failed(self):
        """
        In full output, WARNING: lines follow the check they explain.

        The lkm run produces one failed check with seven explanatory lines, so it must be one
        finding with seven details rather than eight findings.
        """
        findings = self.parse("chkrootkit_one_vuln.txt")
        self.assertEqual(1, len(findings))
        self.assertEqual(7, findings[0].description.count("**Warning:**"))

    def test_quiet_output_warnings_stand_alone(self):
        """
        `chkrootkit -q` prints ONLY the explanatory lines, with no check lines at all.

        A parser that only handled the full shape would import a quiet report as clean, which is the
        report a user is most likely to collect in CI.
        """
        findings = self.parse("chkrootkit_many_vuln.txt")
        self.assertEqual(7, len(findings))
        for finding in findings:
            self.assertTrue(finding.description.startswith("**Warning:**"))
            self.assertNotIn("**Check:**", finding.description)

    def test_many_vuln_titles(self):
        findings = self.parse("chkrootkit_many_vuln.txt")
        titles = [finding.title for finding in findings]
        self.assertIn("chkdirs: Possible LKM Trojan installed (or chkdirs failed):", titles)
        self.assertEqual(
            6, sum(1 for t in titles if "Skipping unsupported filesystem (overlayfs)" in t),
        )

    def test_clean_verdicts_are_not_findings(self):
        """
        Most of chkrootkit's output is passing checks, in several different wordings.

        "not found", "not infected", "not tested" and the started/finished status lines all have to
        be recognised, or a clean run imports as dozens of findings.
        """
        report = io.StringIO(
            "ROOTDIR is `/'\n"
            "Checking `amd'...                                           not found\n"
            "Checking `basename'...                                      not infected\n"
            "Searching for Adore LKM...                                  not tested\n"
            "Checking `lkm'...                                           started\n"
            "Checking `lkm'...                                           finished\n",
        )
        self.assertEqual([], list(ChkrootkitParser().get_findings(report, Test())))

    def test_an_unknown_verdict_is_reported_rather_than_dropped(self):
        """
        The clean list is explicit, so anything unrecognised becomes a finding.

        Guessing the other way would silently hide a verdict this parser has not seen.
        """
        report = io.StringIO("Checking `something'...  some new verdict\n")
        findings = list(ChkrootkitParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("Checking `something': some new verdict", findings[0].title)
        self.assertEqual("Medium", findings[0].severity)

    def test_infected_is_more_severe_than_a_warning(self):
        report = io.StringIO(
            "Checking `du'...                                            INFECTED\n"
            "Checking `find'...                                          WARNING\n"
            "Checking `login'...                                         "
            "Vulnerable but disabled\n",
        )
        findings = list(ChkrootkitParser().get_findings(report, Test()))
        self.assertEqual(["High", "Medium", "Low"], [f.severity for f in findings])

    def test_infected_with_ports_detail(self):
        report = io.StringIO("Checking `bindshell'...   INFECTED (PORTS:  465)\n")
        finding = list(ChkrootkitParser().get_findings(report, Test()))[0]
        self.assertEqual("High", finding.severity)
        self.assertIn("INFECTED (PORTS:  465)", finding.title)

    def test_a_clean_check_ends_the_previous_explanation_block(self):
        """A warning must not collect explanations belonging to a later, unrelated check."""
        report = io.StringIO(
            "Checking `a'...   WARNING\n"
            "WARNING: belongs to a\n"
            "Checking `b'...   not infected\n"
            "WARNING: stands alone\n",
        )
        findings = list(ChkrootkitParser().get_findings(report, Test()))
        self.assertEqual(2, len(findings))
        self.assertIn("belongs to a", findings[0].description)
        self.assertNotIn("stands alone", findings[0].description)
        self.assertEqual("stands alone", findings[1].title)

    def test_bytes_input(self):
        report = io.BytesIO(b"WARNING: something\n")
        findings = list(ChkrootkitParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("something", findings[0].title)

    def test_empty_report(self):
        self.assertEqual([], list(ChkrootkitParser().get_findings(io.StringIO(""), Test())))
