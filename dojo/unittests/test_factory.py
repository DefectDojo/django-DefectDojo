from django.test import TestCase
from dojo.tools.factory import get_parser
from dojo.models import Test


class TestFactory(TestCase):
    def test_get_parser(self):
        with self.subTest(scan_type="Acunetix Scan"):
            scan_type = "Acunetix Scan"
            testfile = open("dojo/unittests/scans/acunetix/one_finding.xml")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="Anchore Engine Scan"):
            scan_type = "Anchore Engine Scan"
            testfile = open("dojo/unittests/scans/anchore/one_vuln.json")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="Nessus Scan"):
            scan_type = "Nessus Scan"
            testfile = open("dojo/unittests/scans/nessus/nessus_v_unknown.xml")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="ZAP Scan"):
            scan_type = "ZAP Scan"
            testfile = open("dojo/unittests/scans/zap/some_2.9.0.xml")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()
