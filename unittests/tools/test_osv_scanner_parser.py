from os import path
from ..dojo_test_case import DojoTestCase
from dojo.tools.osv_scanner.parser import OSVScannerParser
from dojo.models import Test


class TestOSVScannerParser(DojoTestCase):
    def test_no_findings(self):
        with open(path.join(path.dirname(__file__), "../scans/osv-scanner/no_findings.json")) as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))
    
    def test_some_findings(self):
        with open(path.join(path.dirname(__file__), "../scans/osv_scanner/some_findings.json")) as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_many_findings(self):
        with open(path.join(path.dirname(__file__), "../scans/osv_scanner/many_findings.json")) as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))