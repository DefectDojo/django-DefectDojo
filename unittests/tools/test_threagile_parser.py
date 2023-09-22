from dojo.models import Test
from dojo.tools.threagile.parser import ThreagileParser
from unittests.dojo_test_case import DojoTestCase


class TestThreAgileParser(DojoTestCase):
    def test_non_threagile_file_raises_error(self):
        with open("unittests/scans/threagile/bad_formatted_risks_file.json") as testfile:
            parser = ThreagileParser()
            with self.assertRaises(ValueError) as exc_context:
                parser.get_findings(testfile, Test())
            exc = exc_context.exception
            self.assertEqual("Invalid ThreAgile risks file", str(exc))

    def test_empty_file_returns_no_findings(self):
        with open("unittests/scans/threagile/empty_file_no_risks.json") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_file_with_vulnerabilities_returns_correct_findings(self):
        with open("unittests/scans/threagile/risks.json") as testfile:
            parser = ThreagileParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            finding = findings[0]
            self.assertEqual("unguarded-direct-datastore-access", finding.title)
            self.assertEqual("\u003cb\u003eUnguarded Direct Datastore Access\u003c/b\u003e of \u003cb\u003ePoliciesRegoStorage\u003c/b\u003e by \u003cb\u003eEnergon\u003c/b\u003e via \u003cb\u003eEnergonToPolicyRegoFileStorage\u003c/b\u003e", finding.description)
            self.assertEqual("High", finding.severity)
            self.assertEqual("unguarded-direct-datastore-access@energon-ta>energontopolicyregofilestorage@energon-ta@policies-rego-storage-ta", finding.unique_id_from_tool)
            self.assertEqual("501", finding.cwe)
            self.assertEqual("medium", finding.impact)