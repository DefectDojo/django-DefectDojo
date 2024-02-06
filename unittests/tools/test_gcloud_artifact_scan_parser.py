from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.gcloud_artifact_scan.parser import GCloudArtifactScanParser
from dojo.models import Test


class TestGCloudArtifactScanParser(DojoTestCase):
    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with open(f"{get_unit_tests_path()}/scans/gcloud_artifact_scan/many_vulns.json") as testfile:
            parser = GCloudArtifactScanParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(7, len(findings))
        finding = findings[0]
        self.assertEqual("projects/goog-vulnz/notes/CVE-2023-29405", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[1]
        self.assertEqual("projects/goog-vulnz/notes/CVE-2023-29402", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[2]
        self.assertEqual("projects/goog-vulnz/notes/CVE-2023-29404", finding.title)
        self.assertEqual("Critical", finding.severity)
