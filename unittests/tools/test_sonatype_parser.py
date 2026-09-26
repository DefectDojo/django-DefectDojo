from django.test import override_settings

from dojo.models import Test
from dojo.tools.sonatype.identifier import ComponentIdentifier
from dojo.tools.sonatype.parser import SonatypeParser, get_dependency_from_component
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSonatypeParser(DojoTestCase):
    def test_parse_file_with_two_vulns(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "two_vulns.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
        self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
        self.assertEqual("CVE-2016-2402", findings[0].unsaved_vulnerability_ids[0])

    def test_parse_file_with_many_vulns(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "many_vulns.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(6, len(findings))

    def test_parse_file_with_long_file_path(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "long_file_path.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_find_no_vuln(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "no_vuln.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_component_parsed_correctly(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "many_vulns.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("sonatype-2023-4856 - okhttp com.squareup.okhttp 2.6.0", findings[5].title)
        self.assertEqual("okhttp", findings[5].component_name)
        self.assertEqual("2.6.0", findings[5].component_version)

    def test_severity_parsed_correctly(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "many_vulns.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("Medium", findings[0].severity)
        self.assertEqual("High", findings[1].severity)
        self.assertEqual("High", findings[2].severity)
        self.assertEqual("Medium", findings[3].severity)
        self.assertEqual("Medium", findings[4].severity)
        self.assertEqual("Medium", findings[5].severity)

    def test_cwe_parsed_correctly(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "many_vulns.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("693", findings[5].cwe)

    def test_cvssv3_parsed_correctly(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "many_vulns.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N", findings[5].cvssv3)

    def test_filepath_parsed_correctly(self):
        testfile = (get_unit_tests_scans_path("sonatype") / "many_vulns.json").open(encoding="utf-8")
        parser = SonatypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual("WEB-INF/lib/okhttp-2.6.0.jar", findings[5].file_path)

    def parse_with_locations(self, filename, *, locations_enabled):
        test = Test()
        with override_settings(V3_FEATURE_LOCATIONS=locations_enabled), \
                (get_unit_tests_scans_path("sonatype") / filename).open(encoding="utf-8") as testfile:
            findings = SonatypeParser().get_findings(testfile, test)
        return findings, test

    def assert_known_components_unchanged(self, findings, *, locations_enabled):
        expected = [
            ("CVE-2016-2402 - okhttp com.squareup.okhttp 2.6.0", "okhttp", "2.6.0",
             "WEB-INF/lib/okhttp-2.6.0.jar"),
            ("CVE-2022-42889 - commons-text org.apache.commons 1.9", "commons-text", "1.9",
             "WEB-INF/lib/commons-text-1.9.jar"),
            ("CVE-2019-12384 - jackson-databind com.fasterxml.jackson.core 2.9.8", "jackson-databind", "2.9.8",
             "WEB-INF/lib/jackson-databind-2.9.8.jar"),
        ]
        for finding, (title, name, version, file_path) in zip(findings[:3], expected, strict=True):
            self.assertEqual(title, finding.title)
            self.assertEqual(name, finding.component_name)
            self.assertEqual(version, finding.component_version)
            self.assertEqual(file_path, finding.file_path)
            self.assertEqual(len(getattr(finding, "unsaved_locations", [])), 1 if locations_enabled else 0)

    def test_null_component_identifier_with_issues(self):
        for locations_enabled in (False, True):
            with self.subTest(locations_enabled=locations_enabled):
                findings, _ = self.parse_with_locations(
                    "null_component_identifier_with_issues.json", locations_enabled=locations_enabled)
                self.assertEqual(4, len(findings))
                self.assert_known_components_unchanged(findings, locations_enabled=locations_enabled)
                finding = findings[3]
                self.assertEqual("CVE-2099-0001 - unknown-binary.jar", finding.title)
                self.assertEqual("unknown-binary.jar", finding.component_name)
                self.assertEqual("", finding.component_version)
                self.assertEqual("WEB-INF/lib/unknown-binary.jar", finding.file_path)
                self.assertEqual(["CVE-2099-0001"], finding.unsaved_vulnerability_ids)
                self.assertEqual([], getattr(finding, "unsaved_locations", []))

    def test_null_component_identifier_no_security_data(self):
        for locations_enabled in (False, True):
            with self.subTest(locations_enabled=locations_enabled):
                findings, test = self.parse_with_locations(
                    "null_component_identifier_no_security.json", locations_enabled=locations_enabled)
                self.assertEqual(3, len(findings))
                self.assert_known_components_unchanged(findings, locations_enabled=locations_enabled)
                self.assertEqual([], test.unsaved_metadata)

    def test_null_component_identifier_empty_security_issues(self):
        for locations_enabled in (False, True):
            with self.subTest(locations_enabled=locations_enabled):
                findings, test = self.parse_with_locations(
                    "null_component_identifier_empty_issues.json", locations_enabled=locations_enabled)
                self.assertEqual(3, len(findings))
                self.assert_known_components_unchanged(findings, locations_enabled=locations_enabled)
                self.assertEqual([], test.unsaved_metadata)

    def test_unidentified_component_falls_back_to_package_url_then_pathnames(self):
        identifier = ComponentIdentifier({
            "componentIdentifier": None,
            "packageUrl": "pkg:maven/com.example/widget@1.2.3?type=jar",
            "pathnames": ["lib/widget.jar"],
        })
        self.assertEqual("widget 1.2.3", identifier.component_id)
        self.assertEqual("widget", identifier.component_name)
        self.assertEqual("1.2.3", identifier.component_version)

        identifier = ComponentIdentifier({"componentIdentifier": None, "pathnames": ["lib/a.jar", "lib/b.jar"]})
        self.assertEqual("lib/a.jar", identifier.component_id)
        self.assertEqual("lib/a.jar", identifier.component_name)
        self.assertEqual("", identifier.component_version)

        identifier = ComponentIdentifier({"componentIdentifier": {"format": "maven", "coordinates": None},
                                          "displayName": "mystery.jar"})
        self.assertEqual("mystery.jar", identifier.component_name)

    def test_no_dependency_for_unidentified_component(self):
        self.assertIsNone(get_dependency_from_component({"componentIdentifier": None}))
        self.assertIsNone(get_dependency_from_component({"componentIdentifier": {"format": None}}))
