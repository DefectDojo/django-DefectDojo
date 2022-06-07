from os import path
from ..dojo_test_case import DojoTestCase
from dojo.tools.bundler_audit.parser import BundlerAuditParser
from dojo.models import Test


class TestBundlerAuditParser(DojoTestCase):
    def test_get_findings(self):
        with open(path.join(path.dirname(__file__), "../scans/bundler_audit/bundler-audit_v0.6.1.txt")) as testfile:
            parser = BundlerAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEquals("Gem rack: Possible XSS vulnerability in Rack [CVE-2018-16471]", finding.title)
                self.assertEquals("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEquals("CVE-2018-16471", finding.unsaved_vulnerability_ids[0])
                self.assertEquals("rack", finding.component_name)
                self.assertEquals("1.4.7", finding.component_version)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEquals("Gem sprockets: Path Traversal in Sprockets [CVE-2018-3760]", finding.title)
                self.assertEquals("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEquals("CVE-2018-3760", finding.unsaved_vulnerability_ids[0])
                self.assertEquals("sprockets", finding.component_name)
                self.assertEquals("2.2.3", finding.component_version)

    def test_get_findings_version9(self):
        with open(path.join(path.dirname(__file__), "../scans/bundler_audit/version_9.0.txt")) as testfile:
            parser = BundlerAuditParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEquals("Gem rack: Directory traversal in Rack::Directory app bundled with Rack [CVE-2020-8161]", finding.title)
                self.assertEquals("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEquals("CVE-2020-8161", finding.unsaved_vulnerability_ids[0])
                self.assertEquals("rack", finding.component_name)
                self.assertEquals("1.6.13", finding.component_version)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEquals("Gem rack: Percent-encoded cookies can be used to overwrite existing prefixed cookie names [CVE-2020-8184]", finding.title)
                self.assertEquals("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEquals("CVE-2020-8184", finding.unsaved_vulnerability_ids[0])
                self.assertEquals("rack", finding.component_name)
                self.assertEquals("1.6.13", finding.component_version)
            with self.subTest(i=2):
                finding = findings[2]
                self.assertEquals("Gem sprockets: Path Traversal in Sprockets [CVE-2018-3760]", finding.title)
                self.assertEquals("Medium", finding.severity)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
                self.assertEquals("CVE-2018-3760", finding.unsaved_vulnerability_ids[0])
                self.assertEquals("sprockets", finding.component_name)
                self.assertEquals("2.2.3", finding.component_version)
