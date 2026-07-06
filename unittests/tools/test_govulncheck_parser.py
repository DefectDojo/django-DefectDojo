from dojo.models import Test
from dojo.tools.govulncheck.parser import GovulncheckParser, GovulncheckParserV2
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGovulncheckParser(DojoTestCase):

    def test_parse_empty(self):
        with self.assertRaises(ValueError) as exp, \
          (get_unit_tests_scans_path("govulncheck") / "empty.json").open(encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            parser.get_findings(testfile, Test())
        self.assertIn(
            "Invalid JSON format", str(exp.exception),
        )

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("govulncheck") / "no_vulns.json").open(encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("govulncheck") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(3, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("GO-2022-1144", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2022-41717", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.19.0", finding.component_version)
                self.assertEqual("GO-2022-1144", finding.unique_id_from_tool)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1144", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertEqual("https://go.dev/issue/56350", finding.references)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("GO-2022-1143", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2022-41720", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.19.0", finding.component_version)
                self.assertEqual("GO-2022-1143", finding.unique_id_from_tool)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1143", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertEqual("https://go.dev/issue/56694", finding.references)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("GO-2022-0969", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2022-27664", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.19.0", finding.component_version)
                self.assertEqual("GO-2022-0969", finding.unique_id_from_tool)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-0969", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertEqual("https://groups.google.com/g/golang-announce/c/x49AQzIVX-s", finding.references)

    def test_parse_new_version_no_findings(self):
        with (get_unit_tests_scans_path("govulncheck") / "no_vulns_new_version.json").open(encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_new_version_many_findings(self):
        with (get_unit_tests_scans_path("govulncheck") / "many_vulns_new_version.json").open(encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("GO-2023-1840 - stdlib - runtime", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("CVE-2023-29403", finding.cve)
                self.assertEqual("stdlib", finding.component_name)
                self.assertEqual("v1.20.1", finding.component_version)
                self.assertEqual("GO-2023-1840", finding.unique_id_from_tool)
                self.assertEqual("runtime", finding.file_path)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2023-1840", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.references)

    def test_parse_new_version_many_findings_custom_severity(self):
        with (get_unit_tests_scans_path("govulncheck") / "many_vulns_new_version_custom_severity.json").open(encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(2, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Low", finding.severity)
                self.assertEqual("GO-2021-0113 - golang.org/x/text - golang.org/x/text/language", finding.title)
                self.assertEqual("CVE-2021-38561", finding.cve)
                self.assertEqual("golang.org/x/text", finding.component_name)
                self.assertEqual("v0.3.5", finding.component_version)
                self.assertEqual("GO-2021-0113", finding.unique_id_from_tool)
                self.assertEqual("golang.org/x/text/language", finding.file_path)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2021-0113", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.references)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("High", finding.severity)
                self.assertEqual("GO-2022-1059 - golang.org/x/text - golang.org/x/text/language", finding.title)
                self.assertEqual("CVE-2022-32149", finding.cve)
                self.assertEqual("golang.org/x/text", finding.component_name)
                self.assertEqual("v0.3.5", finding.component_version)
                self.assertEqual("GO-2022-1059", finding.unique_id_from_tool)
                self.assertEqual("golang.org/x/text/language", finding.file_path)
                self.assertEqual("https://pkg.go.dev/vuln/GO-2022-1059", finding.url)
                self.assertIsNotNone(finding.impact)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.references)
                self.assertTrue(finding.fix_available)
                self.assertEqual("0.3.8", finding.fix_version)

    def test_parse_issue_14642(self):
        with (get_unit_tests_scans_path("govulncheck") / "issue_14642.json").open(encoding="utf-8") as testfile:
            parser = GovulncheckParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(201, len(findings))

    def test_parse_sarif_is_rejected(self):
        # A govulncheck SARIF report uploaded to this scan type fails with a
        # clear message pointing to the SARIF scan type (issue #15033 follow-up).
        with self.assertRaises(ValueError) as exp, \
          (get_unit_tests_scans_path("govulncheck") / "issue_15033_sarif.json").open(encoding="utf-8") as testfile:
            GovulncheckParser().get_findings(testfile, Test())
        self.assertIn("SARIF", str(exp.exception))


class TestGovulncheckParserV2(DojoTestCase):

    def test_parse_empty(self):
        with self.assertRaises(ValueError) as exp, \
          (get_unit_tests_scans_path("govulncheck") / "empty.json").open(encoding="utf-8") as testfile:
            GovulncheckParserV2().get_findings(testfile, Test())
        self.assertIn("Invalid JSON format", str(exp.exception))

    def test_parse_no_findings(self):
        # The old dict format is ignored by v2 (it only handles the streaming list format).
        with (get_unit_tests_scans_path("govulncheck") / "no_vulns.json").open(encoding="utf-8") as testfile:
            findings = GovulncheckParserV2().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_issue_15033(self):
        with (get_unit_tests_scans_path("govulncheck") / "issue_15033.json").open(encoding="utf-8") as testfile:
            findings = GovulncheckParserV2().get_findings(testfile, Test())

            # One finding per (osv, module); advisories that do not apply to the
            # scanned code are not imported (the old parser produced 234).
            self.assertEqual(72, len(findings))

            severities = [f.severity for f in findings]
            # Reachability-based severity, separate per tier: symbol=High, package=Low, module=Info.
            self.assertEqual(29, severities.count("High"))
            self.assertEqual(17, severities.count("Low"))
            self.assertEqual(26, severities.count("Info"))

            # Every finding maps to a vulnerable component.
            self.assertTrue(all(f.component_name for f in findings))

            # unique_id_from_tool encodes (osv, module) so multi-module advisories split.
            self.assertEqual(len({f.unique_id_from_tool for f in findings}), len(findings))

            first = findings[0]
            self.assertEqual("GO-2024-3333 - golang.org/x/net", first.title)
            # Highest reachability level seen for this (osv, module) wins: package -> Low.
            self.assertEqual("Low", first.severity)
            self.assertEqual("CVE-2024-45338", first.cve)
            self.assertEqual("golang.org/x/net", first.component_name)
            self.assertEqual("v0.25.0", first.component_version)
            self.assertEqual("GO-2024-3333:golang.org/x/net", first.unique_id_from_tool)
            self.assertTrue(first.fix_available)
            self.assertEqual("v0.33.0", first.fix_version)
            self.assertEqual("https://pkg.go.dev/vuln/GO-2024-3333", first.url)

    def test_parse_sarif_is_rejected(self):
        # A govulncheck SARIF report uploaded to this scan type fails with a
        # clear message pointing to the SARIF scan type (issue #15033 follow-up).
        with self.assertRaises(ValueError) as exp, \
          (get_unit_tests_scans_path("govulncheck") / "issue_15033_sarif.json").open(encoding="utf-8") as testfile:
            GovulncheckParserV2().get_findings(testfile, Test())
        self.assertIn("SARIF", str(exp.exception))
