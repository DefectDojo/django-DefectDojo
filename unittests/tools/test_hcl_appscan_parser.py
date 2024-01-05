from ..dojo_test_case import DojoTestCase
from dojo.tools.hcl_appscan.parser import HCLAppScanParser


class TestHCLAppScanParser(DojoTestCase):

    def test_no_findings(self):
        my_file_handle = open("unittests/scans/hcl_appscan/no_findings.xml")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(0, len(findings))

    def test_many_findings(self):
        my_file_handle = open("unittests/scans/hcl_appscan/many_findings.xml")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(60, len(findings))
        self.assertEqual(findings[0].title, " Unencrypted Login Request_ mani-virtual-machine_ /dvja-1.0-SNAPSHOT/register.action")
        self.assertEqual(findings[1].title, " Unencrypted Login Request_ mani-virtual-machine_ /dvja-1.0-SNAPSHOT/login.action;jsessionid=AD12F9CF7835CC92885A381859462BAC")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[9].severity, "Medium")
        self.assertEqual(findings[5].mitigation, "Remediation: fix_61640\nAdvisory: GD_autocompleteInForm")

    def test_issue_9279(self):
        my_file_handle = open("unittests/scans/hcl_appscan/issue_9279.xml")
        parser = HCLAppScanParser()
        findings = parser.get_findings(my_file_handle, None)
        my_file_handle.close()
        self.assertEqual(113, len(findings))
        self.assertEqual(findings[0].title, " attUnnecessaryResponseHeaders_ 7089695691196187648_ insecureWebAppConfiguration")
        self.assertEqual(findings[1].title, " attHttpsToHttp_ 7089695691196187648_ sensitiveDataNotSSL")
        self.assertEqual(findings[0].severity, "Low")
        self.assertEqual(findings[5].mitigation, "Remediation: fix_61771\nAdvisory: attReferrerPolicyHeaderExist")
