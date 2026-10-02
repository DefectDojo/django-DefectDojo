import io

from dojo.models import Finding, Test
from dojo.tools.yara.parser import YaraParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestYaraParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("yara") / filename).open(encoding="utf-8") as file:
            return list(YaraParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = YaraParser()
        self.assertEqual(["YARA Scan"], parser.get_scan_types())
        self.assertEqual("YARA Scan", parser.get_label_for_scan_types("YARA Scan"))
        self.assertIn("-m", parser.get_description_for_scan_types("YARA Scan"))

    def test_no_vuln(self):
        """
        Yara prints NOTHING when no rule matches, and still exits 0.

        The fixture is that real zero-byte capture, and it has to parse rather than raise.
        """
        self.assertEqual(0, (get_unit_tests_scans_path("yara") / "yara_no_vuln.txt").stat().st_size)
        self.assertEqual(0, len(self.parse("yara_no_vuln.txt")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("yara_one_vuln.txt")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `yara -s -m` run over local sample files."""
        findings = self.parse("yara_one_vuln.txt")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "Suspicious_Reverse_Shell_Command matched /scan/targets/helper.sh",
            finding.title,
        )
        # severity = "high" in the rule metadata.
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("/scan/targets/helper.sh", finding.file_path)
        self.assertEqual("Suspicious_Reverse_Shell_Command", finding.vuln_id_from_tool)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Rule:** Suspicious_Reverse_Shell_Command", finding.description)
        self.assertIn(
            "**Rule description:** Shell command that reconnects to an attacker-controlled host",
            finding.description,
        )
        # Whatever else the ruleset recorded is kept, because which keys it uses is its own choice.
        self.assertIn("**author:** generic-ruleset", finding.description)
        self.assertIn("**reference:** https://example.com/rules/reverse-shell", finding.description)
        # -s adds the offset of each matched string.
        self.assertIn("`0x1f` $bash: bash -i >& /dev/tcp/", finding.description)

    def test_many_vuln(self):
        findings = self.parse("yara_many_vuln.txt")
        self.assertEqual(6, len(findings))
        self.assertEqual(
            [
                "Awkward_Metadata_Values matched /scan/targets/awkward.txt",
                "Debug_Endpoint_Left_Enabled matched /scan/targets/app.conf",
                "Hardcoded_Placeholder_Credential matched /scan/targets/app.conf",
                "Rule_With_No_Metadata_At_All matched /scan/targets/build.txt",
                "Suspicious_Reverse_Shell_Command matched /scan/targets/helper.sh",
                "Unrated_Marker_String matched /scan/targets/build.txt",
            ],
            sorted(finding.title for finding in findings),
        )

    def test_severity_comes_from_rule_metadata(self):
        """A ruleset that records a severity is believed; the scale is the rule author's."""
        findings = {finding.vuln_id_from_tool: finding.severity for finding in self.parse("yara_many_vuln.txt")}
        self.assertEqual("Critical", findings["Awkward_Metadata_Values"])
        self.assertEqual("High", findings["Suspicious_Reverse_Shell_Command"])
        self.assertEqual("Medium", findings["Hardcoded_Placeholder_Credential"])
        self.assertEqual("Low", findings["Debug_Endpoint_Left_Enabled"])

    def test_a_rule_with_no_severity_falls_back_to_medium(self):
        """
        What a YARA match MEANS is entirely up to the rule, so with no severity recorded there is
        nothing to read and the finding takes the default.
        """
        findings = {finding.vuln_id_from_tool: finding.severity for finding in self.parse("yara_many_vuln.txt")}
        # One rule has metadata but no severity, one has no metadata at all.
        self.assertEqual("Medium", findings["Unrated_Marker_String"])
        self.assertEqual("Medium", findings["Rule_With_No_Metadata_At_All"])

    def test_awkward_metadata_values_survive(self):
        """
        A metadata value can hold a comma and an escaped quote, so splitting on commas is wrong.

        yara also prints an INTEGER value as `key =90` - a space before the "=" but not after -
        while string and boolean values get no space at all.
        """
        finding = next(
            f for f in self.parse("yara_many_vuln.txt")
            if f.vuln_id_from_tool == "Awkward_Metadata_Values"
        )
        self.assertIn(
            '**Rule description:** Matches a marker, then reports it as "awkward"',
            finding.description,
        )
        self.assertIn("**confidence:** 90", finding.description)
        self.assertIn("**experimental:** true", finding.description)

    def test_output_without_m_or_s_still_parses(self):
        """
        Plain `yara rules target` prints only the rule name and the path.

        That is the default invocation, so it has to work - with the default severity, since there is
        no metadata to read.
        """
        findings = self.parse("yara_default_output.txt")
        self.assertEqual(6, len(findings))
        for finding in findings:
            self.assertEqual("Medium", finding.severity)
            self.assertNotIn("**Matched:**", finding.description)

    def test_several_matched_strings_stay_one_finding(self):
        """A rule matching a file twice is one finding, with both offsets in the description."""
        finding = next(
            f for f in self.parse("yara_many_vuln.txt")
            if f.vuln_id_from_tool == "Hardcoded_Placeholder_Credential"
        )
        self.assertIn('`0x0` $a: password = "CHANGEME"', finding.description)
        self.assertIn('`0x16` $b: api_key = "AKIAPLACEHOLDER"', finding.description)

    def test_the_same_rule_on_two_files_stays_two_findings(self):
        report = io.StringIO(
            "Some_Rule /scan/one.txt\n"
            "Some_Rule /scan/two.txt\n",
        )
        findings = list(YaraParser().get_findings(report, Test()))
        self.assertEqual(2, len(findings))
        self.assertEqual(["/scan/one.txt", "/scan/two.txt"], sorted(f.file_path for f in findings))

    def test_a_path_containing_spaces_is_kept_whole(self):
        report = io.StringIO('Some_Rule [severity="low"] /scan/a folder/with spaces.txt\n')
        finding = list(YaraParser().get_findings(report, Test()))[0]
        self.assertEqual("/scan/a folder/with spaces.txt", finding.file_path)
        self.assertEqual("Low", finding.severity)

    def test_a_matched_string_containing_a_colon_is_not_truncated(self):
        """The matched text is file content, so only the first two colons are separators."""
        report = io.StringIO(
            "Some_Rule /scan/x.txt\n"
            "0x10:$url: https://example.com/a:b\n",
        )
        finding = list(YaraParser().get_findings(report, Test()))[0]
        self.assertIn("`0x10` $url: https://example.com/a:b", finding.description)

    def test_an_unknown_severity_word_falls_back_to_the_default(self):
        report = io.StringIO('Some_Rule [severity="catastrophic"] /scan/x.txt\n')
        finding = list(YaraParser().get_findings(report, Test()))[0]
        self.assertEqual("Medium", finding.severity)

    def test_empty_metadata_brackets(self):
        report = io.StringIO("Some_Rule [] /scan/x.txt\n")
        finding = list(YaraParser().get_findings(report, Test()))[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("/scan/x.txt", finding.file_path)

    def test_empty_report(self):
        self.assertEqual([], list(YaraParser().get_findings(io.StringIO(""), Test())))

    def test_bytes_input(self):
        report = io.BytesIO(b'Some_Rule [severity="high"] /scan/x.txt\n')
        findings = list(YaraParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)
