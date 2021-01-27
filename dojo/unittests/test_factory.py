from django.test import TestCase
from dojo.tools.factory import import_parser_factory
from dojo.models import Test


class TestFactory(TestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open('dojo/unittests/scans/acunetix/one_finding.xml')
        parser = import_parser_factory(testfile, Test(), False, False, 'Acunetix Scan')
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
