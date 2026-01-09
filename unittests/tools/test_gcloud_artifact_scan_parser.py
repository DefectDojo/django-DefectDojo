from dojo.models import Test
from dojo.tools.gcloud_artifact_scan.parser import GCloudArtifactScanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGCloudArtifactScanParser(DojoTestCase):
    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        with (get_unit_tests_scans_path("gcloud_artifact_scan") / "many_vulns.json").open(encoding="utf-8") as testfile:
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
        self.assertEqual("CVE-2023-29404", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_artifact_analysis_occurrences_sample(self):
        with (get_unit_tests_scans_path("gcloud_artifact_scan") / "artifact-analysis-occurrences-sample.json").open(encoding="utf-8") as testfile:
            parser = GCloudArtifactScanParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(12, len(findings))
        finding = findings[0]
        self.assertEqual("projects/goog-vulnz/notes/CVE-2023-36665", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[1]
        self.assertEqual("projects/goog-vulnz/notes/CVE-2023-45853", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[2]
        self.assertEqual("projects/goog-vulnz/notes/CVE-2022-37620", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertEqual("CVE-2022-37620", finding.unsaved_vulnerability_ids[0])
