from datetime import datetime
from ..dojo_test_case import DojoTestCase
from dojo.tools.gitlab_container_scan.parser import GitlabContainerScanParser
from dojo.models import Test


class TestGitlabContainerScanParser(DojoTestCase):

    def test_gitlab_container_scan_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/gitlab_container_scan/gl-container-scanning-report-0-vuln.json")
        parser = GitlabContainerScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_gitlab_container_scan_parser_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/gitlab_container_scan/gl-container-scanning-report-1-vuln.json")
        parser = GitlabContainerScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        first_finding = findings[0]
        self.assertEqual(1, len(findings))
        self.assertEqual(datetime(2021, 4, 14, 19, 46, 18), finding.date)
        self.assertEqual("CVE-2019-3462 in apt-1.4.8", first_finding.title)
        self.assertEqual("apt", first_finding.component_name)
        self.assertEqual("1.4.8", first_finding.component_version)
        self.assertEqual(1, len(first_finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-3462", first_finding.unsaved_vulnerability_ids[0])
        self.assertEqual("High", first_finding.severity)
        self.assertEqual("Upgrade apt from 1.4.8 to 1.4.9", first_finding.mitigation)
        self.assertEqual("df52bc8ce9a2ae56bbcb0c4ecda62123fbd6f69b", first_finding.unique_id_from_tool)

    def test_gitlab_container_scan_parser_with_five_vuln_has_five_findings(self):
        testfile = open("unittests/scans/gitlab_container_scan/gl-container-scanning-report-5-vuln.json")
        parser = GitlabContainerScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
