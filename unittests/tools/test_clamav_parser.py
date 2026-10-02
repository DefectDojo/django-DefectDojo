import io

from dojo.models import Finding, Test
from dojo.tools.clamav.parser import ClamAVParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestClamAVParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("clamav") / filename).open(encoding="utf-8") as file:
            return list(ClamAVParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = ClamAVParser()
        self.assertEqual(["ClamAV Scan"], parser.get_scan_types())
        self.assertEqual("ClamAV Scan", parser.get_label_for_scan_types("ClamAV Scan"))
        self.assertIn("--allmatch", parser.get_description_for_scan_types("ClamAV Scan"))

    def test_no_vuln(self):
        """
        A clean clamscan still writes output: an "OK" line per file and a SCAN SUMMARY block.

        None of that is a finding, so the fixture - a real clean run - parses to zero.
        """
        content = (get_unit_tests_scans_path("clamav") / "clamav_no_vuln.txt").read_text(encoding="utf-8")
        self.assertIn(": OK", content)
        self.assertIn("Infected files: 0", content)

        self.assertEqual(0, len(self.parse("clamav_no_vuln.txt")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("clamav_one_vuln.txt")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real clamscan run against a local file."""
        findings = self.parse("clamav_one_vuln.txt")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "Malware detected: Generic.Placeholder.Alpha.UNOFFICIAL in /scan/targets/artifact-one.bin",
            finding.title,
        )
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(506, finding.cwe)
        self.assertEqual("/scan/targets/artifact-one.bin", finding.file_path)
        self.assertEqual("Generic.Placeholder.Alpha.UNOFFICIAL", finding.vuln_id_from_tool)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**File:** /scan/targets/artifact-one.bin", finding.description)
        self.assertIn("**Signature:** Generic.Placeholder.Alpha.UNOFFICIAL", finding.description)
        self.assertIn("false positive", finding.mitigation)

    def test_many_vuln(self):
        """A mixed directory: three files matched a signature and one is clean."""
        findings = self.parse("clamav_many_vuln.txt")
        self.assertEqual(3, len(findings))
        self.assertEqual(
            [
                "/scan/mixed/artifact-one.bin",
                "/scan/mixed/artifact-three.bin",
                "/scan/mixed/artifact-two.bin",
            ],
            sorted(finding.file_path for finding in findings),
        )

    def test_a_clean_file_in_a_mixed_scan_is_not_a_finding(self):
        content = (get_unit_tests_scans_path("clamav") / "clamav_many_vuln.txt").read_text(encoding="utf-8")
        self.assertIn("/scan/mixed/ordinary.bin: OK", content)

        self.assertNotIn(
            "/scan/mixed/ordinary.bin",
            [finding.file_path for finding in self.parse("clamav_many_vuln.txt")],
        )

    def test_allmatch_reports_every_signature_for_one_file(self):
        """
        Clamscan stops at the first signature per file unless --allmatch is passed.

        With it, one file can produce several detections, and each signature is its own finding.
        """
        findings = self.parse("clamav_allmatch.txt")
        self.assertEqual(2, len(findings))
        self.assertEqual(
            {"/scan/targets/artifact-three.bin"},
            {finding.file_path for finding in findings},
        )
        self.assertEqual(
            ["Generic.Placeholder.Alpha.UNOFFICIAL", "Generic.Placeholder.Gamma.UNOFFICIAL"],
            sorted(finding.vuln_id_from_tool for finding in findings),
        )

    def test_the_unofficial_suffix_is_explained(self):
        """
        ClamAV appends .UNOFFICIAL to any signature that did not come from its own database.

        That changes how much the detection is worth, so it is called out rather than stripped.
        """
        finding = self.parse("clamav_one_vuln.txt")[0]
        self.assertIn("came from a database other than ClamAV's own", finding.description)

    def test_an_official_signature_gets_no_such_note(self):
        report = io.StringIO("/scan/x.bin: Win.Trojan.Placeholder-1 FOUND\n")
        finding = list(ClamAVParser().get_findings(report, Test()))[0]
        self.assertNotIn("UNOFFICIAL", finding.description)
        self.assertEqual("Win.Trojan.Placeholder-1", finding.vuln_id_from_tool)

    def test_the_scan_summary_is_not_imported(self):
        """The summary holds a scan date and an engine version, and neither belongs in a finding."""
        for finding in self.parse("clamav_many_vuln.txt"):
            self.assertNotIn("Engine version", finding.description)
            self.assertNotIn("Start Date", finding.description)

    def test_an_unreadable_file_is_not_a_finding(self):
        """Clamscan reports a file it could not read with ERROR, which is not a detection."""
        report = io.StringIO(
            "/scan/locked.bin: Access denied. ERROR\n"
            "/scan/empty.bin: Empty file\n"
            "/scan/real.bin: Some.Signature FOUND\n",
        )
        findings = list(ClamAVParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("/scan/real.bin", findings[0].file_path)

    def test_a_path_containing_a_colon_or_a_space_is_kept_whole(self):
        """The FOUND suffix is anchored to the end of the line, so the path can contain anything."""
        report = io.StringIO("/scan/a dir/odd: name.bin: Some.Signature FOUND\n")
        finding = list(ClamAVParser().get_findings(report, Test()))[0]
        self.assertEqual("/scan/a dir/odd: name.bin", finding.file_path)
        self.assertEqual("Some.Signature", finding.vuln_id_from_tool)

    def test_a_repeated_line_collapses(self):
        report = io.StringIO(
            "/scan/x.bin: Some.Signature FOUND\n"
            "/scan/x.bin: Some.Signature FOUND\n",
        )
        self.assertEqual(1, len(list(ClamAVParser().get_findings(report, Test()))))

    def test_the_same_signature_in_two_files_stays_two_findings(self):
        report = io.StringIO(
            "/scan/one.bin: Some.Signature FOUND\n"
            "/scan/two.bin: Some.Signature FOUND\n",
        )
        self.assertEqual(2, len(list(ClamAVParser().get_findings(report, Test()))))

    def test_empty_report(self):
        self.assertEqual([], list(ClamAVParser().get_findings(io.StringIO(""), Test())))

    def test_bytes_input(self):
        report = io.BytesIO(b"/scan/x.bin: Some.Signature FOUND\n")
        self.assertEqual(1, len(list(ClamAVParser().get_findings(report, Test()))))
