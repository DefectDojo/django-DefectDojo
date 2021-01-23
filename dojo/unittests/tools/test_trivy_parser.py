import os.path

from django.test import TestCase
from dojo.tools.trivy.parser import TrivyParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join('dojo/unittests/scans/trivy', file_name)


class TestTrivyParser(TestCase):

    def setUp(self):
        self.dojo_test = Test()

    def test_mixed_scan(self):
        with open(sample_path('trivy_mix.json')) as test_file:
            trivy_parser = TrivyParser(test_file, self.dojo_test)
        self.assertEqual(len(trivy_parser.items), 6)
        self.check_title(trivy_parser.items)
        self.check_cve(trivy_parser.items)
        self.check_cwe(trivy_parser.items)

    def check_title(self, trivy_findings):
        self.assertEqual(trivy_findings[0].title, 'CVE-2018-16487 lodash 4.17.4')
        self.assertEqual(trivy_findings[1].title, 'CVE-2018-16840 curl 7.61.0-r0')

    def check_cve(self, trivy_findings):
        self.assertEqual(trivy_findings[0].cve, 'CVE-2018-16487')
        self.assertEqual(trivy_findings[1].cve, 'CVE-2018-16840')

    def check_cwe(self, trivy_findings):
        self.assertEqual(trivy_findings[0].cwe, '190')
        self.assertEqual(trivy_findings[1].cwe, 0)
