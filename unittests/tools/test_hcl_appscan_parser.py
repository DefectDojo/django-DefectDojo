from ..dojo_test_case import DojoTestCase
from dojo.tools.hcl_appscan.parser import HCLAppScanParser


class TestHCLAppScanParser(DojoTestCase):

    def test_no_findings(self):
        my_file_handle = open("unittests/scans/hcl_appscan/no_findings.xml")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_one_finding(self):
        my_file_handle = open("unittests/scans/hcl_appscan/one_finding.xml")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(1, len(findings))

    def test_many_findings(self):
        my_file_handle = open("unittests/scans/hcl_appscan/many_findings.xml")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(60, len(findings))
