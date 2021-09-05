from django.test import SimpleTestCase
from dojo.tools.veracode_pipeline.parser import VeracodePipelineParser
from dojo.models import Test


class TestVeracodePipelineScannerParser(SimpleTestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/veracode_pipeline/one_finding.json")
        parser = VeracodePipelineParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_findings(self):
        testfile = open("dojo/unittests/scans/veracode_pipeline/multiple_findings.json")
        parser = VeracodePipelineParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        finding = findings[0]
        self.assertEqual('99f326aa-d648-4c11-ac0c-a583460c370d|1', finding.unique_id_from_tool)
        self.assertEqual("Critical", finding.severity)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(123, finding.cwe)
        self.assertEqual('Issue Type', finding.title)
        self.assertEqual('display text', finding.description)
        self.assertEqual('filename', finding.sourcefile)
        self.assertEqual(24, finding.sast_source_line)
        self.assertEqual('fname()', finding.sast_source_object)
        self.assertEqual('54859332', finding.hash_code)

        finding = findings[1]
        self.assertEqual('99f326aa-d648-4c11-ac0c-a583460c370d|2', finding.unique_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(456, finding.cwe)
        self.assertEqual('Another Issue Type', finding.title)
        self.assertEqual('another display text', finding.description)
        self.assertEqual('different_filename', finding.sourcefile)
        self.assertEqual(89, finding.sast_source_line)
        self.assertEqual('view()', finding.sast_source_object)
        self.assertEqual('87151532', finding.hash_code)
