from django.test import TestCase
from dojo.tools.sysdig_reports.parser import SysdigReportsParser
from dojo.models import Test


class TestSysdigParser(TestCase):

    def test_sysdig_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/sysdig_reports/sysdig_reports_zero_vul.csv")
        parser = SysdigReportsParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_sysdig_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("unittests/scans/sysdig_reports/sysdig_reports_one_vul.csv")
        parser = SysdigReportsParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("com.fasterxml.jackson.core:jackson-databind", findings[0].component_name)
        self.assertEqual("2.9.7", findings[0].component_version)
        self.assertEqual("CVE-2018-19360", findings[0].cve)

    def test_sysdig_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/sysdig_reports/sysdig_reports_many_vul.csv")
        parser = SysdigReportsParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(50, len(findings))

    def test_sysdig_parser_missing_cve_field_id_from_csv_file(self):
        with self.assertRaises(ValueError) as context:
            testfile = open("unittests/scans/sysdig_reports/sysdig_reports_missing_cve_field.csv")
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertTrue(
                "sysdig report contains errors:" in str(context.exception)
            )
            self.assertTrue("ECONNREFUSED" in str(context.exception))

    def test_sysdig_parser_missing_cve_field_not_starting_with_cve(self):
        with self.assertRaises(ValueError) as context:
            testfile = open("unittests/scans/sysdig_reports/sysdig_reports_not_starting_with_cve.csv")
            parser = SysdigReportsParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertTrue(
                "sysdig report contains errors:" in str(context.exception)
            )
            self.assertTrue("ECONNREFUSED" in str(context.exception))
