from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.kubebench.parser import KubeBenchParser
from dojo.models import Test


class TestKubeBenchParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/kubebench/kube-bench-report-zero-vuln.json"
        )
        parser = KubeBenchParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open(
            get_unit_tests_path() + "/scans/kubebench/kube-bench-report-one-vuln.json"
        )
        parser = KubeBenchParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/kubebench/kube-bench-report-many-vuln.json"
        )
        parser = KubeBenchParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 4)

    def test_parse_file_with_controls_tag(self):

        # The testfile has been derived from https://github.com/kubernetes-sigs/wg-policy-prototypes/blob/master/policy-report/kube-bench-adapter/samples/kube-bench-output.json
        testfile = open(
            get_unit_tests_path() + "/scans/kubebench/kube-bench-controls.json"
        )
        parser = KubeBenchParser()
        findings = parser.get_findings(testfile, Test())

        medium_severities = 0
        info_severities = 0
        for finding in findings:
            if finding.severity == 'Medium':
                medium_severities += 1
            if finding.severity == 'Info':
                info_severities += 1

        self.assertEqual(36, medium_severities)
        self.assertEqual(20, info_severities)

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("1.1.1 - Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Automated)", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.mitigation)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertEqual("1.1.1", finding.vuln_id_from_tool)
