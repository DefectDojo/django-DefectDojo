from os import path

from django.test import TestCase
from dojo.models import Test
from dojo.tools.factory import import_parser_factory


class TestFactory(TestCase):

    def test_acunetix_one_finding(self):
        testfile = open(path.join(path.dirname(__file__), "tools/scans/acunetix/one_finding.xml"))
        parser = import_parser_factory(testfile, Test(), False, False, 'Acunetix Scan')
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_anchore_one_finding(self):
        testfile = open(path.join(path.dirname(__file__), "tools/scans/anchore/one_vuln.json"))
        parser = import_parser_factory(testfile, Test(), False, False, 'Anchore Engine Scan')
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_nessus(self):
        testfile = open(path.join(path.dirname(__file__), "tools/nessus/nessus_v_unknown.xml"))
        parser = import_parser_factory(testfile, Test(), False, False, 'Nessus Scan')
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(32, len(findings))
