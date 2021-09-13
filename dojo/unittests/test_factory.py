from django.test import TestCase
from dojo.tools.factory import get_parser
from dojo.models import Test


class TestFactory(TestCase):

    def test_acunetix_one_finding(self):
        testfile = open('dojo/unittests/scans/acunetix/one_finding.xml')
        parser = get_parser('Acunetix Scan')
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_anchore_one_finding(self):
        testfile = open("dojo/unittests/scans/anchore/one_vuln.json")
        parser = get_parser('Anchore Engine Scan')
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_nessus(self):
        testfile = open("dojo/unittests/scans/nessus/nessus_v_unknown.xml")
        parser = get_parser('Nessus Scan')
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(32, len(findings))
