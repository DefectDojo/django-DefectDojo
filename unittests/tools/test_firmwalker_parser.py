import io

from dojo.models import Finding, Test
from dojo.tools.firmwalker.parser import FirmwalkerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFirmwalkerParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("firmwalker") / filename).open(encoding="utf-8") as file:
            return list(FirmwalkerParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = FirmwalkerParser()
        self.assertEqual(["Firmwalker Scan"], parser.get_scan_types())
        self.assertEqual("Firmwalker Scan", parser.get_label_for_scan_types("Firmwalker Scan"))
        self.assertIn("firmwalker.sh", parser.get_description_for_scan_types("Firmwalker Scan"))

    def test_no_vuln(self):
        """
        Firmwalker writes its whole section skeleton whether or not it finds anything.

        The clean fixture is a real 3.4kB report over a firmware tree with nothing of interest in it,
        and the only content line in it is the scanned directory - which is not a hit.
        """
        content = (get_unit_tests_scans_path("firmwalker") / "firmwalker_no_vuln.txt").read_text(
            encoding="utf-8",
        )
        self.assertIn("***Firmware Directory***", content)
        self.assertIn("/fwempty/", content)

        self.assertEqual(0, len(self.parse("firmwalker_no_vuln.txt")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("firmwalker_one_vuln.txt")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real firmwalker run over a local firmware tree."""
        findings = self.parse("firmwalker_one_vuln.txt")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("/etc/ssl/cert.pem (SSL related files)", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("/etc/ssl/cert.pem", finding.file_path)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("searching for SSL related files", finding.description)
        self.assertIn("**Path:** /etc/ssl/cert.pem", finding.description)
        self.assertIn("**Patterns that matched:** *.pem", finding.description)

    def test_the_directory_listing_section_is_not_imported(self):
        """
        Firmwalker drops a plain `ls -la` of etc/ssl into the report.

        Those lines look like hits, so without skipping the section the clean report above would
        produce findings for "total 0" and for a listing line carrying a modification time - which
        changes between runs of an unchanged image.
        """
        content = (get_unit_tests_scans_path("firmwalker") / "firmwalker_one_vuln.txt").read_text(
            encoding="utf-8",
        )
        self.assertIn("***List etc/ssl directory***", content)
        self.assertIn("total 0", content)

        for finding in self.parse("firmwalker_one_vuln.txt"):
            self.assertNotIn("total 0", finding.description)
            self.assertNotEqual("total 0", finding.file_path)

    def test_many_vuln(self):
        findings = self.parse("firmwalker_many_vuln.txt")
        self.assertEqual(20, len(findings))
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_severity_is_info_because_firmwalker_points_rather_than_judges(self):
        """
        Firmwalker reports where to look, not that something is wrong.

        A private key file is a problem in a shipped image and expected in a development one, and
        firmwalker cannot tell which it is looking at.
        """
        findings = self.parse("firmwalker_many_vuln.txt")
        keys = [f for f in findings if f.file_path == "/etc/ssl/private/device.key"]
        self.assertEqual(1, len(keys))
        self.assertEqual("Info", keys[0].severity)

    def test_overlapping_patterns_collapse_into_one_finding(self):
        """
        Firmwalker searches both an exact name and a glob, so one file is reported twice.

        authorized_keys is found by "authorized_keys" and by "*authorized_keys*"; that is one finding
        naming both patterns rather than two identical ones.
        """
        content = (get_unit_tests_scans_path("firmwalker") / "firmwalker_many_vuln.txt").read_text(
            encoding="utf-8",
        )
        self.assertEqual(3, content.count("/home/admin/.ssh/authorized_keys"))

        findings = [
            f for f in self.parse("firmwalker_many_vuln.txt")
            if f.file_path == "/home/admin/.ssh/authorized_keys"
        ]
        ssh = next(f for f in findings if "SSH related files" in f.title)
        self.assertIn("**Patterns that matched:** authorized_keys, *authorized_keys*", ssh.description)

    def test_the_same_file_in_two_sections_stays_two_findings(self):
        """
        A file found by a name search AND by a content search is two different observations.

        /etc/passwd is a password file and also mentions "admin" and "root", so it is reported once
        per section with the patterns of that section.
        """
        findings = [
            f for f in self.parse("firmwalker_many_vuln.txt") if f.file_path == "/etc/passwd"
        ]
        self.assertEqual(2, len(findings))
        self.assertEqual(
            ["/etc/passwd (password files)", "/etc/passwd (patterns in files)"],
            sorted(finding.title for finding in findings),
        )
        patterns = next(f for f in findings if "patterns in files" in f.title)
        self.assertIn("**Patterns that matched:** admin, root", patterns.description)

    def test_a_grep_style_hit_is_split_into_path_and_match(self):
        """
        The hash section reports "path:matched-text", and it uses an ABSOLUTE path.

        firmwalker's file searches print paths relative to the firmware root while this section
        prints the path it was given, so the two do not agree - that is the tool's own behaviour and
        the report is taken as it is.
        """
        finding = next(
            f for f in self.parse("firmwalker_many_vuln.txt") if "Unix-MD5" in f.title
        )
        self.assertEqual("/fw/etc/shadow", finding.file_path)
        self.assertEqual("/fw/etc/shadow (Unix-MD5 hashes)", finding.title)
        self.assertIn("**Matched:** $1$AAAAAAAA$BBBBBBBBBBBBBBBBBBBBBB", finding.description)

    def test_an_address_url_or_email_gets_no_file_path(self):
        """Those sections report values found inside files, not files, so file_path stays unset."""
        findings = {
            f.title: f for f in self.parse("firmwalker_many_vuln.txt")
            if f.file_path is None
        }
        self.assertEqual(
            [
                "203.0.113.20 (ip addresses)",
                "admin@example.com (emails)",
                "https://updates.example.com (urls)",
                "support@example.com (emails)",
            ],
            sorted(findings),
        )
        self.assertIn("**Value:** 203.0.113.20", findings["203.0.113.20 (ip addresses)"].description)

    def test_a_url_is_not_split_on_its_colon(self):
        """Only a hit starting with "/" is split, or "https" would become the path."""
        finding = next(
            f for f in self.parse("firmwalker_many_vuln.txt") if "urls" in f.title
        )
        self.assertIn("https://updates.example.com", finding.title)
        self.assertNotIn("**Matched:**", finding.description)

    def test_a_hit_before_any_section_is_ignored(self):
        report = io.StringIO(
            "/stray/line/before/any/section\n"
            "***Search for password files***\n"
            "##################################### passwd\n"
            "/etc/passwd\n",
        )
        findings = list(FirmwalkerParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("/etc/passwd", findings[0].file_path)

    def test_empty_report(self):
        self.assertEqual([], list(FirmwalkerParser().get_findings(io.StringIO(""), Test())))

    def test_bytes_input(self):
        report = io.BytesIO(
            b"***Search for password files***\n"
            b"##################################### passwd\n"
            b"/etc/passwd\n",
        )
        self.assertEqual(1, len(list(FirmwalkerParser().get_findings(report, Test()))))
