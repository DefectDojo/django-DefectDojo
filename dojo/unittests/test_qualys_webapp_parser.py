from django.test import TestCase
from dojo.tools.qualys_webapp.parser import QualysWebAppParser
from dojo.models import Test


class TestPhpSymfonySecurityCheckerParser(TestCase):

    def test_qualys_webapp_parser_without_file_has_no_findings(self):
        parser = QualysWebAppParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_qualys_webapp_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/qualys_webapp/qualys_webapp_no_vuln.xml")
        parser = QualysWebAppParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_qualys_webapp_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/qualys_webapp/qualys_webapp_one_vuln.xml")
        parser = QualysWebAppParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_qualys_webapp_parser_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/qualys_webapp/qualys_webapp_many_vuln.xml")
        parser = QualysWebAppParser(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(parser.items))
