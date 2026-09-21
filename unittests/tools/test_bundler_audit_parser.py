
from dojo.models import Test
from dojo.tools.bundler_audit.parser import BundlerAuditParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBundlerAuditParser(DojoTestCase):
    def test_get_findings(self):
        with (get_unit_tests_scans_path("bundler_audit") / "bundler-audit_v0.6.1.txt").open(encoding="utf-8") as testfile:
            parser = BundlerAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Gem rack: Possible XSS vulnerability in Rack [CVE-2018-16471]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2018-16471", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("rack", finding.component_name)
                self.assertEqual("1.4.7", finding.component_version)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Gem sprockets: Path Traversal in Sprockets [CVE-2018-3760]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2018-3760", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("sprockets", finding.component_name)
                self.assertEqual("2.2.3", finding.component_version)

    def test_get_findings_version9(self):
        with (get_unit_tests_scans_path("bundler_audit") / "version_9.0.txt").open(encoding="utf-8") as testfile:
            parser = BundlerAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Gem rack: Directory traversal in Rack::Directory app bundled with Rack [CVE-2020-8161]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2020-8161", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("rack", finding.component_name)
                self.assertEqual("1.6.13", finding.component_version)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Gem rack: Percent-encoded cookies can be used to overwrite existing prefixed cookie names [CVE-2020-8184]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2020-8184", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("rack", finding.component_name)
                self.assertEqual("1.6.13", finding.component_version)
            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Gem sprockets: Path Traversal in Sprockets [CVE-2018-3760]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("CVE-2018-3760", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("sprockets", finding.component_name)
                self.assertEqual("2.2.3", finding.component_version)
            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("Gem nokogiri: Improper Handling of Unexpected Data Type in Nokogiri [GHSA-xc9x-jj77-9p9j]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEqual("GHSA-xc9x-jj77-9p9j", finding.unsaved_vulnerability_ids[0])
                self.assertEqual("nokogiri", finding.component_name)
                self.assertEqual("1.15.2", finding.component_version)

    def test_get_findings_missing_optional_fields(self):
        """A warning missing optional fields must not inherit the previous warning's values."""
        with (get_unit_tests_scans_path("bundler_audit") / "partial_fields.txt").open(encoding="utf-8") as testfile:
            parser = BundlerAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Gem rack: Directory traversal in Rack::Directory app bundled with Rack [CVE-2020-8161]", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("upgrade to ~> 2.1.3, >= 2.2.0", finding.mitigation)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Gem sprockets [CVE-2018-3760]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNone(finding.mitigation)
                self.assertEqual("sprockets", finding.component_name)
                self.assertEqual("2.2.3", finding.component_version)

    def test_get_findings_without_advisory_id(self):
        """A warning carrying no Advisory/CVE/GHSA line must parse instead of raising."""
        with (get_unit_tests_scans_path("bundler_audit") / "no_advisory_id.txt").open(encoding="utf-8") as testfile:
            parser = BundlerAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Gem nokogiri: Advisory reported without an assigned identifier", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("nokogiri", finding.component_name)
            self.assertEqual("1.15.2", finding.component_version)
            self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_get_findings_incomplete_warning_first(self):
        """An incomplete warning with no preceding warning to inherit from must parse."""
        with (get_unit_tests_scans_path("bundler_audit") / "incomplete_first.txt").open(encoding="utf-8") as testfile:
            parser = BundlerAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Gem sprockets [CVE-2018-3760]", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertIsNone(finding.mitigation)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Gem rack: Directory traversal in Rack::Directory app bundled with Rack [CVE-2020-8161]", finding.title)
                self.assertEqual("High", finding.severity)
