from dojo.models import Product, Engagement, Test
from dojo.tools.checkmarx_cxflow_sast.parser import CheckmarxCXFlowSastParser
from ..dojo_test_case import DojoTestCase, get_unit_tests_path

import dateutil.parser


class TestCheckmarxCxflowSast(DojoTestCase):

    def init(self, reportFilename):
        my_file_handle = open(reportFilename)
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        return my_file_handle, product, engagement, test

    def test_file_name_aggregated_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle, product, engagement, test = self.init(
            get_unit_tests_path() + "/scans/checkmarx_cxflow_sast/no_finding.json"
        )
        parser = CheckmarxCXFlowSastParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(0, len(findings))

    def test_file_name_aggregated_parse_file_with_no_vulnerabilities_has_1_finding(self):
        my_file_handle, product, engagement, test = self.init(
            get_unit_tests_path() + "/scans/checkmarx_cxflow_sast/1-finding.json"
        )
        parser = CheckmarxCXFlowSastParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertIn("Reflected XSS All Clients", finding.title)
        self.assertEqual(79, finding.cwe)
        self.assertEqual(dateutil.parser.parse("Sunday, January 19, 2020 2:40:11 AM"), finding.date)
        self.assertEqual("14660819" + "88", finding.unique_id_from_tool)
        self.assertEqual("getRawParameter", finding.sast_source_object)
        self.assertEqual("username", finding.sast_sink_object)
        self.assertEqual("DOS_Login.java", finding.sast_source_file_path)
        self.assertEqual("88", finding.sast_source_line)
        self.assertEqual("14660819", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertEqual("107", finding.line)
        self.assertEqual(False, finding.false_p)
        self.assertIn("Java", finding.description)
        self.assertIn("http://CX-FLOW-CLEAN/CxWebClient/ViewerMain.aspx?scanid=1000026&projectid=6&pathid=2",
                      finding.description)
        self.assertIn("PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 "
                      "2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,"
                      "NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site "
                      "Scripting (XSS)", finding.description)
        self.assertEqual(True, finding.active)
        self.assertEqual(False, finding.verified)

    def test_file_name_aggregated_parse_file_with_no_vulnerabilities_has_11_finding(self):
        my_file_handle, product, engagement, test = self.init(
            get_unit_tests_path() + "/scans/checkmarx_cxflow_sast/4-findings.json"
        )
        parser = CheckmarxCXFlowSastParser()
        findings = parser.get_findings(my_file_handle, test)
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.date)
            self.assertIsNotNone(finding.sast_source_object)
            self.assertIsNotNone(finding.unique_id_from_tool)
            self.assertIsNotNone(finding.sast_sink_object)
            self.assertIsNotNone(finding.sast_source_file_path)
            self.assertIsNotNone(finding.sast_source_line)
            self.assertIsNotNone(finding.vuln_id_from_tool)
            self.assertIsNotNone(finding.severity)
            self.assertIsNotNone(finding.line)
            self.assertIsNotNone(finding.false_p)
            self.assertIsNotNone(finding.description)
