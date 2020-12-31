from django.test import TestCase
from dojo.tools.ossindex_devaudit.parser import OssIndexDevauditParser
from dojo.models import Test


class TestOssIndexDevauditParser(TestCase):

    def test_ossindex_devaudit_parser_without_file_has_no_findings(self):
        parser = OssIndexDevauditParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_ossindex_devaudit_parser_with_no_vulns_has_no_findings(self):
        testfile = open("dojo/unittests/scans/ossindex_devaudit_sample/ossindex_devaudit_no_vuln.json")
        parser = OssIndexDevauditParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_ossindex_devaudit_parser_with_one_critical_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/ossindex_devaudit_sample/ossindex_devaudit_one_vuln.json")
        parser = OssIndexDevauditParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))

    def test_ossindex_devaudit_parser_with_multiple_vulns_has_multiple_finding(self):
        testfile = open("dojo/unittests/scans/ossindex_devaudit_sample/ossindex_devaudit_multiple_vulns.json")
        parser = OssIndexDevauditParser(testfile, Test())
        testfile.close()
        self.assertTrue(len(parser.items) > 1)

    def test_ossindex_devaudit_parser_with_no_cve_returns_unknown_severity(self):
        testfile = open("dojo/unittests/scans/ossindex_devaudit_sample/ossindex_devaudit_vuln_no_cvssscore.json")
        parser = OssIndexDevauditParser(testfile, Test())
        testfile.close()
        print(parser.items)
        self.assertTrue(len(parser.items) == 1)
