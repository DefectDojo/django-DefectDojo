from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.dockerbench.parser import DockerBenchParser
from dojo.models import Test


class TestDockerBenchParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dockerbench/docker-bench-report-zero-vulns.json"
        )
        parser = DockerBenchParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dockerbench/docker-bench-report-single-vuln.json"
        )
        parser = DockerBenchParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dockerbench/docker-bench-report-many-vulns.json"
        )
        parser = DockerBenchParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 50)
        self.assertTrue(sum(1 for f in findings if f.severity.upper() == 'CRITICAL') == 0)
        self.assertTrue(sum(1 for f in findings if f.severity.upper() == 'HIGH') == 33)
        self.assertTrue(sum(1 for f in findings if f.severity.upper() == 'LOW') == 16)
        self.assertTrue(sum(1 for f in findings if f.severity.upper() == 'INFO') == 1)
