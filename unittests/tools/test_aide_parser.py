import io

from dojo.models import Finding, Test
from dojo.tools.aide.parser import AideParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestAideParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("aide") / filename).open(encoding="utf-8") as file:
            return list(AideParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = AideParser()
        self.assertEqual(["AIDE Scan"], parser.get_scan_types())
        self.assertEqual("AIDE Scan", parser.get_label_for_scan_types("AIDE Scan"))
        self.assertIn("aide --check", parser.get_description_for_scan_types("AIDE Scan"))

    def test_no_vuln(self):
        """A matching baseline reports no differences and no entry sections at all."""
        self.assertEqual(0, len(self.parse("aide_no_vuln.txt")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("aide_one_vuln.txt")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `aide --check` after modifying one watched file."""
        findings = self.parse("aide_one_vuln.txt")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("File changed: /watched/a.txt", finding.title)
        self.assertEqual("/watched/a.txt", finding.file_path)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertIsNone(getattr(finding, "line", None))

        self.assertIn("**Change:** changed", finding.description)
        self.assertIn("**Attribute mask:** `f > ... ....H`", finding.description)

    def test_aide_reports_a_path_unlike_the_other_host_tools(self):
        """AIDE tracks files, so unlike Lynis or rkhunter it gives a real path to report."""
        finding = self.parse("aide_one_vuln.txt")[0]
        self.assertTrue(finding.file_path.startswith("/"))

    def test_many_vuln(self):
        findings = self.parse("aide_many_vuln.txt")
        self.assertEqual(5, len(findings))
        for finding in findings:
            self.assertTrue(finding.dynamic_finding)
            self.assertTrue(finding.file_path.startswith("/watched/"))

    def test_all_three_change_types_are_walked(self):
        """
        AIDE groups differences into Added, Removed and Changed sections.

        Each is a separate block in the report, so missing one would silently drop findings.
        """
        findings = self.parse("aide_many_vuln.txt")
        by_change = {}
        for finding in findings:
            change = finding.title.split(":")[0].removeprefix("File ").strip()
            by_change.setdefault(change, []).append(finding.file_path)
        self.assertEqual({"added", "removed", "changed"}, set(by_change))
        self.assertEqual(["/watched/d.txt", "/watched/e.txt"], sorted(by_change["added"]))
        self.assertEqual(["/watched/c.txt"], by_change["removed"])
        self.assertEqual(["/watched/a.txt", "/watched/b.txt"], sorted(by_change["changed"]))

    def test_attribute_diffs_are_joined_to_the_changed_entry(self):
        """
        The attribute diffs live in their own section keyed by path, not beside the entry.

        The two halves of the report have to be joined up or a changed file arrives with no detail.
        """
        findings = self.parse("aide_many_vuln.txt")
        permissions = next(f for f in findings if f.file_path == "/watched/b.txt")
        self.assertIn("**Attributes that changed:**", permissions.description)
        self.assertIn("- Perm: -rw-r--r-- | -rwxrwxrwx", permissions.description)

    def test_added_entries_have_no_attribute_diffs(self):
        findings = self.parse("aide_many_vuln.txt")
        added = next(f for f in findings if f.file_path == "/watched/d.txt")
        self.assertNotIn("**Attributes that changed:**", added.description)

    def test_wrapped_checksums_are_joined_column_by_column(self):
        """
        AIDE wraps a long value onto a continuation line, keeping old and new in their own columns.

        Appending the whole continuation would splice the tail of the old checksum onto the head of
        the new one, producing two values that are both wrong.
        """
        report = io.StringIO(
            "AIDE found differences between database and filesystem!!\n"
            "\n"
            "---------------------------------------------------\n"
            "Changed entries:\n"
            "---------------------------------------------------\n"
            "\n"
            "f > ... ....H      : /watched/a.txt\n"
            "\n"
            "---------------------------------------------------\n"
            "Detailed information about changes:\n"
            "---------------------------------------------------\n"
            "\n"
            "File: /watched/a.txt\n"
            " SHA256    : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
            "             aaaaaaaaaaa=                     | bbbbbbbbbbb=\n",
        )
        finding = list(AideParser().get_findings(report, Test()))[0]
        self.assertIn(
            "- SHA256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaa= | "
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBbbbbbbbbbbb=",
            finding.description,
        )

    def test_summary_and_database_sections_are_not_mistaken_for_entries(self):
        """
        The report ends with database checksums that look like attribute lines.

        Only the three entry sections yield findings, so the Summary and database blocks must not
        leak in - the clean report is almost entirely those two sections.
        """
        with (get_unit_tests_scans_path("aide") / "aide_no_vuln.txt").open(encoding="utf-8") as file:
            content = file.read()
        self.assertIn("The attributes of the (uncompressed) database(s)", content)
        self.assertIn("SHA256", content)
        self.assertEqual(0, len(self.parse("aide_no_vuln.txt")))

    def test_bytes_input(self):
        report = io.BytesIO(
            b"Removed entries:\n"
            b"---------------------------------------------------\n"
            b"f------------------: /watched/gone.txt\n",
        )
        findings = list(AideParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("File removed: /watched/gone.txt", findings[0].title)

    def test_empty_report(self):
        self.assertEqual([], list(AideParser().get_findings(io.StringIO(""), Test())))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("aide_one_vuln.txt")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("/watched/a.txt", locations[0].data["file_path"])
        self.assertIsNone(locations[0].data["line"])
