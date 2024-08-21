from django.test import TestCase

from dojo.models import Test
from dojo.tools.threat_composer.parser import ThreatComposerParser


class TestThreatComposerParser(TestCase):

    def test_threat_composer_parser_with_no_threat_has_no_findings(self):
        testfile = open("unittests/scans/threat_composer/threat_composer_zero_threats.json")
        parser = ThreatComposerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_threat_composer_parser_with_one_threat_has_one_finding(self):
        testfile = open("unittests/scans/threat_composer/threat_composer_one_threat.json")
        parser = ThreatComposerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(1, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("lorem ipsum", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertTrue(
                "Assumption" in str(finding.description),
            )
            self.assertIsNotNone(finding.mitigation)
            self.assertTrue(
                "Assumption" in str(finding.mitigation),
            )
            self.assertIsNotNone(finding.impact)
            self.assertEqual("46db1eb4-a451-4d05-afe1-c695491e2387", finding.unique_id_from_tool)
            self.assertEqual(23, finding.vuln_id_from_tool)
            self.assertFalse(finding.false_p)
            self.assertFalse(finding.verified)

    def test_threat_composer_parser_with_many_threats_has_many_findings(self):
        testfile = open("unittests/scans/threat_composer/threat_composer_many_threats.json")
        parser = ThreatComposerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(21, len(findings))

    def test_threat_composer_parser_empty_with_error(self):
        testfile = open("unittests/scans/threat_composer/threat_composer_no_threats_with_error.json")
        parser = ThreatComposerParser()
        with self.assertRaises(ValueError) as context:
            parser.get_findings(testfile, Test())

        testfile.close()
        self.assertTrue(
            "No threats found in the JSON file" in str(context.exception),
        )

    def test_threat_composer_parser_with_one_threat_has_not_assumptions(self):
        testfile = open("unittests/scans/threat_composer/threat_composer_broken_assumptions.json")
        parser = ThreatComposerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        finding = findings[0]
        self.assertFalse(
            "Assumption" in str(finding.description),
        )

    def test_threat_composer_parser_with_one_threat_has_not_mitigations(self):
        testfile = open("unittests/scans/threat_composer/threat_composer_broken_mitigations.json")
        parser = ThreatComposerParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        finding = findings[0]
        self.assertFalse(
            "Mitigation" in str(finding.mitigation),
        )
