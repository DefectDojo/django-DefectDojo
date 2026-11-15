
from unittest.mock import Mock

from defusedxml import ElementTree

from dojo.models import Test
from dojo.tools.burp_dastardly.parser import BurpDastardlyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBurpParser(DojoTestCase):

    def test_burp_dastardly_multiple_findings(self):
        with (get_unit_tests_scans_path("burp_dastardly") / "many_findings.xml").open(encoding="utf-8") as test_file:
            parser = BurpDastardlyParser()
            findings = parser.get_findings(test_file, Test())
            self.validate_locations(findings)
            self.assertEqual(4, len(findings))

    def test_burp_dastardly_empty_report(self):
        """A legitimate empty report must keep parsing as zero findings."""
        with (get_unit_tests_scans_path("burp_dastardly") / "empty_report.xml").open(encoding="utf-8") as test_file:
            parser = BurpDastardlyParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(0, len(findings))

    def test_burp_dastardly_unexpected_root_rejected(self):
        """A well-formed document with an unsupported root must not be
        treated as an empty scan (which would mitigate findings on reimport)."""
        with (get_unit_tests_scans_path("burp_dastardly") / "unexpected_root.xml").open(encoding="utf-8") as test_file:
            parser = BurpDastardlyParser()
            with self.assertRaises(ValueError):
                parser.get_findings(test_file, Test())

    def test_burp_dastardly_namespaced_root_rejected(self):
        """get_items searches un-namespaced children only, so a namespaced
        document would silently produce zero findings; reject it instead."""
        with (get_unit_tests_scans_path("burp_dastardly") / "namespaced_root.xml").open(encoding="utf-8") as test_file:
            parser = BurpDastardlyParser()
            with self.assertRaises(ValueError):
                parser.get_findings(test_file, Test())

    def test_burp_dastardly_malformed_report_keeps_parse_error(self):
        """Malformed XML must keep raising ParseError (not ValueError)."""
        parser = BurpDastardlyParser()
        with self.assertRaises(ElementTree.ParseError):
            parser.get_findings(Mock(read=lambda: b"<testsuites"), Test())
