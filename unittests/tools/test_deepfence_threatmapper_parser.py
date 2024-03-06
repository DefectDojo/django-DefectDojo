from ..dojo_test_case import DojoTestCase
from dojo.tools.deepfence_threatmapper.parser import DeepfenceThreatmapperParser
from dojo.models import Test


class TestChefInspectParser(DojoTestCase):

    def test_parse_file_compliance_report(self):
        testfile = open("unittests/scans/deepfence_threatmapper/compliance_report.csv")
        parser = DeepfenceThreatmapperParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_malware_report(self):
        testfile = open("unittests/scans/deepfence_threatmapper/malware_report.csv")
        parser = DeepfenceThreatmapperParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_secret_report(self):
        testfile = open("unittests/scans/deepfence_threatmapper/secret_report.csv")
        parser = DeepfenceThreatmapperParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(10, len(findings))
