from dojo.models import Finding, Test
from dojo.tools.seal.parser import SealParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSealParser(DojoTestCase):
    def parse(self, file_name):
        with (get_unit_tests_scans_path("seal") / file_name).open(encoding="utf-8") as testfile:
            return SealParser().get_findings(testfile, Test())

    def test_parse_file_with_no_vuln(self):
        # A scan without findings leaves the export file empty, without even a header
        self.assertEqual(0, len(self.parse("no_vuln.csv")))

    def test_parse_file_with_header_only(self):
        self.assertEqual(0, len(self.parse("no_vuln_header_only.csv")))

    def test_parse_file_with_one_vuln(self):
        findings = self.parse("one_vuln.csv")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("lodash 4.17.15 - CVE-2021-23337", finding.title)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("lodash", finding.component_name)
        self.assertEqual("4.17.15", finding.component_version)
        self.assertEqual("CVE-2021-23337", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2021-23337"], finding.unsaved_vulnerability_ids)
        self.assertTrue(finding.fix_available)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertIn("NPM", finding.description)
        self.assertIn("4.17.15-sp1", finding.mitigation)

    def test_parse_file_with_many_vulns(self):
        findings = self.parse("many_vulns.csv")
        self.assertEqual(8, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("lodash 4.17.15 - CVE-2021-23337", finding.title)
            self.assertEqual("lodash", finding.component_name)

        with self.subTest(i=1):
            # The second identifier of the same package becomes its own finding
            finding = findings[1]
            self.assertEqual("lodash 4.17.15 - CVE-2020-8203", finding.title)
            self.assertEqual("lodash", finding.component_name)
            self.assertEqual("4.17.15", finding.component_version)

        with self.subTest(i=4):
            # Seal reports GitHub advisory identifiers when a CVE is not assigned
            finding = findings[4]
            self.assertEqual("django 3.2.4 - GHSA-jrh2-hc4r-7jrq", finding.title)
            self.assertEqual(["GHSA-jrh2-hc4r-7jrq"], finding.unsaved_vulnerability_ids)

        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("org.apache.commons:commons-lang3", finding.component_name)
            self.assertFalse(finding.fix_available)
            self.assertEqual("Seal has no sealed version for this package version yet.", finding.mitigation)

        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("github.com/gin-gonic/gin", finding.component_name)
            self.assertIn("1.7.7+sp1", finding.mitigation)

        with self.subTest(i=7):
            # Sealable, but no sealed version published yet: nothing to update to
            finding = findings[7]
            self.assertEqual("requests", finding.component_name)
            self.assertFalse(finding.fix_available)
            self.assertEqual("Seal has no sealed version for this package version yet.", finding.mitigation)

    def test_parse_file_with_shaded_packages(self):
        findings = self.parse("shaded.csv")
        self.assertEqual(3, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("com.example:fat-jar 1.0.0 - CVE-2021-44228", finding.title)
            self.assertEqual("CVE-2021-44228", finding.vuln_id_from_tool)
            self.assertIn("log4j-core", finding.description)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("com.example:other-jar 2.0.0 - CVE-2022-42003", finding.title)
            self.assertIn("jackson-databind, jackson-core", finding.description)

        with self.subTest(i=2):
            # Same package, but this identifier carries no embedding chain
            finding = findings[2]
            self.assertEqual("com.example:other-jar 2.0.0 - CVE-2020-8908", finding.title)
            self.assertNotIn("shaded", finding.description)

    def test_parse_file_with_score_column(self):
        findings = self.parse("with_score.csv")
        self.assertEqual(4, len(findings))
        self.assertEqual("Critical", findings[0].severity)
        self.assertEqual("High", findings[1].severity)
        self.assertEqual("Medium", findings[2].severity)
        self.assertEqual("Low", findings[3].severity)
