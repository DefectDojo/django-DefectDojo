from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.models import Test
from datetime import datetime
from dojo.tools.gitlab.parser import GitlabParser


class TestGitlabParser(DojoTestCase):

    def test_gitlab_get_basics(self):
        parser = GitlabParser()
        scan_types = parser.get_scan_types()
        self.assertEqual(8, len(scan_types))
        self.assertEqual('GitLab SAST Report', parser.get_label_for_scan_types('GitLab SAST Report'))
        self.assertEqual('Import GitLab SAST Report vulnerabilities in JSON format.',
                         parser.get_description_for_scan_types('GitLab SAST Report'))

    def test_gitlab_get_tests(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabParser()
        findings = parser.get_tests("GitLab SAST Report", testfile)
        self.assertEqual(1, len(findings))

    def test_gitlab_get_findings(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test(scan_type="GitLab SAST Report"))
        self.assertEqual(1, len(findings))

    def test_gitlab_scan_type_mismatch(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabParser()
        with self.assertRaises(Exception) as context:
            parser.get_findings(testfile, Test(scan_type="GitLab DAST Report"))
        self.assertTrue('Incopatible scan type. Requested: "dast", format in the file: "sast"' in str(context.exception))


class TestGitlabAPIFuzzingParser(DojoTestCase):
    def test_gitlab_api_fuzzing_parser_with_no_vuln_has_no_findings(self):
        with open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_api_fuzzing/gitlab_api_fuzzing_0_vuln.json"
        ) as testfile:
            parser = GitlabParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_gitlab_api_fuzzing_parser_with_one_criticle_vuln_has_one_findings(self):
        with open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_api_fuzzing/gitlab_api_fuzzing_1_vuln.json"
        ) as testfile:
            parser = GitlabParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            first_finding = findings[0]
            self.assertEqual(first_finding.title, "name")
            self.assertEqual(
                first_finding.description,
                "coverage_fuzzing\nIndex-out-of-range\ngo-fuzzing-example.ParseComplex.func6\ngo-fuzzing-example.ParseComplex\ngo-fuzzing-example.Fuzz\n",
            )
            self.assertEqual(
                first_finding.unique_id_from_tool,
                "c83603d0befefe01644abdda1abbfaac842fccbabfbe336db9f370386e40f702",
            )

    def test_gitlab_api_fuzzing_parser_with_invalid_json(self):
        with open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_api_fuzzing/gitlab_api_fuzzing_invalid.json"
        ) as testfile:
            # Something is wrong with JSON file
            with self.assertRaises((KeyError, ValueError)):
                parser = GitlabParser()
                parser.get_findings(testfile, Test())


class TestGitlabContainerScanParser(DojoTestCase):

    def test_gitlab_container_scan_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/gitlab/gitlab_container_scan/gl-container-scanning-report-0-vuln.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_gitlab_container_scan_parser_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/gitlab/gitlab_container_scan/gl-container-scanning-report-1-vuln.json")
        parser = GitlabParser()
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
        self.assertEqual("CVE-2019-3462", first_finding.cve)
        self.assertEqual("High", first_finding.severity)
        self.assertEqual("Upgrade apt from 1.4.8 to 1.4.9", first_finding.mitigation)
        self.assertEqual("df52bc8ce9a2ae56bbcb0c4ecda62123fbd6f69b", first_finding.unique_id_from_tool)

    def test_gitlab_container_scan_parser_with_five_vuln_has_five_findings(self):
        testfile = open("unittests/scans/gitlab/gitlab_container_scan/gl-container-scanning-report-5-vuln.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))


class TestGitlabDastParser(DojoTestCase):
    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/gitlab/gitlab_dast/gitlab_dast_zero_vul.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("unittests/scans/gitlab/gitlab_dast/gitlab_dast_one_vul.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]

        # endpoint validation
        for endpoint in finding.unsaved_endpoints:
            endpoint.clean()

        self.assertEqual(
            "5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.unique_id_from_tool
        )
        self.assertEqual(3, finding.scanner_confidence)
        # vulnerability does not have a name: fallback to using id as a title
        self.assertEqual("5ec00bbc-2e53-44cb-83e9-3d35365277e3", finding.title)
        self.assertIsInstance(finding.description, str)

        date = finding.date.strftime("%Y-%m-%dT%H:%M:%S.%f")
        self.assertEqual("2021-04-23T15:46:40.615000", date)
        self.assertIsNone(finding.references)  # should be None as there are no links

        self.assertEqual("High", finding.severity)
        self.assertEqual("", finding.mitigation)  # no solution proposed

        self.assertEqual(359, finding.cwe)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("unittests/scans/gitlab/gitlab_dast/gitlab_dast_many_vul.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())

        self.assertEqual(10, len(findings))

        # endpoint validation
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

        # the first one is done above
        finding = findings[1]
        # must-have fields
        self.assertEqual(3, finding.scanner_confidence)
        self.assertTrue("Content Security Policy (CSP)" in finding.description)
        self.assertEqual(False, finding.static_finding)
        self.assertEqual(True, finding.dynamic_finding)

        # conditional fields
        date = finding.date.strftime("%Y-%m-%dT%H:%M:%S.%f")
        self.assertEqual("2021-04-23T15:46:40.644000", date)
        self.assertEqual(
            "87e98ddf-7d75-444a-be6d-45400151a0fe", finding.unique_id_from_tool
        )
        # vulnerability does not have a name: fallback to using id as a title
        self.assertEqual(finding.unique_id_from_tool, finding.title)
        self.assertEqual(16, finding.cwe)
        self.assertTrue("http://www.w3.org/TR/CSP/" in finding.references)
        self.assertEqual("Medium", finding.severity)
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual(str(endpoint), "http://api-server/v1/tree/10")
        self.assertEqual(endpoint.host, "api-server")  # host port path
        self.assertEqual(endpoint.port, 80)
        self.assertEqual(endpoint.path, "v1/tree/10")
        self.assertTrue("Ensure that your web server," in finding.mitigation)


class TestGitlabDepScanParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_dep_scan/gl-dependency-scanning-report-0-vuln.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_dep_scan/gl-dependency-scanning-report-1-vuln.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_two_vuln_has_one_missing_component_(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_dep_scan/gl-dependency-scanning-report-2-vuln-missing-component.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        finding = findings[0]
        self.assertEqual(None, finding.component_name)
        self.assertEqual(None, finding.component_version)
        finding = findings[1]
        self.assertEqual("golang.org/x/crypto", finding.component_name)
        self.assertEqual("v0.0.0-20190308221718-c2843e01d9a2", finding.component_version)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_dep_scan/gl-dependency-scanning-report-many-vuln.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) > 2)


class TestGitlabSastParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-0-vuln.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_sast/gl-sast-report-many-vuln.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(3, len(findings))
        finding = findings[0]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[1]
        self.assertEqual("Password in URL", finding.title)
        self.assertEqual("Critical", finding.severity)
        finding = findings[2]
        self.assertEqual("PKCS8 key", finding.title)
        self.assertEqual("Critical", finding.severity)

    def test_parse_file_with_various_confidences(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_sast/gl-sast-report-confidence.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 8)
        for item in findings:
            self.assertTrue(item.cwe is None or isinstance(item.cwe, int))
        finding = findings[3]
        self.assertEqual("Tentative", finding.get_scanner_confidence_text())
        finding = findings[4]
        self.assertEqual("Tentative", finding.get_scanner_confidence_text())
        finding = findings[5]
        self.assertEqual("Firm", finding.get_scanner_confidence_text())
        finding = findings[6]
        self.assertEqual("Firm", finding.get_scanner_confidence_text())
        finding = findings[7]
        self.assertEqual("Certain", finding.get_scanner_confidence_text())

    def test_parse_file_with_various_cwes(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-cwe.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertTrue(len(findings) == 3)
        self.assertEqual(79, findings[0].cwe)
        self.assertEqual(89, findings[1].cwe)
        self.assertEqual(None, findings[2].cwe)

    def test_parse_file_issue4336(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report_issue4344.json")
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("[None severity] Potential XSS vulnerability", finding.title)

    def test_without_scan(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabParser()
        tests = parser.get_tests(None, testfile)
        self.assertEqual(1, len(tests))
        test = tests[0]
        self.assertIsNone(test.name)
        self.assertIsNone(test.type)
        self.assertIsNone(test.version)
        findings = test.findings
        self.assertEqual(1, len(findings))

    def test_with_scan(self):
        testfile = open("unittests/scans/gitlab/gitlab_sast/gl-sast-report-confidence.json")
        parser = GitlabParser()
        tests = parser.get_tests(None, testfile)
        self.assertEqual(1, len(tests))
        test = tests[0]
        self.assertEqual("njsscan", test.name)
        self.assertEqual("njsscan", test.type)
        self.assertEqual("0.1.9", test.version)
        findings = test.findings
        self.assertEqual(8, len(findings))


class TestGitlabSecretDetectionReportParser(DojoTestCase):
    def test_gitlab_secret_detection_report_parser_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_secret_detection_report/gitlab_secret_detection_report_0_vuln.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_gitlab_secret_detection_report_parser_with_one_vuln_has_one_findings(
            self,
    ):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_secret_detection_report/gitlab_secret_detection_report_1_vuln.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        first_finding = findings[0]
        self.assertEqual(1, len(findings))
        self.assertEqual(datetime(2021, 6, 2, 9, 13, 9), first_finding.date)
        self.assertEqual(5, first_finding.line)
        self.assertEqual("Critical", first_finding.severity)
        self.assertEqual("README.md", first_finding.file_path)
        self.assertEqual("AWS\nAKIAIOSFODNN7EXAMPLE", first_finding.description)
        self.assertEqual(
            "714ed3e4e289ad35a089e0a888e8d0120b6a6083b1090a189cbc6a3227396240",
            first_finding.unique_id_from_tool,
        )

    def test_gitlab_secret_detection_report_parser_with_many_vuln_has_many_findings(
            self,
    ):
        testfile = open(
            get_unit_tests_path() + "/scans/gitlab/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln.json"
        )
        parser = GitlabParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))
