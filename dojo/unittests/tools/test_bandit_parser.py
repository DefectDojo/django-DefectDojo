import datetime
from dateutil.tz import tzlocal
from django.test import TestCase
from dojo.tools.bandit.parser import BanditParser
from dojo.models import Test


class TestBanditParser(TestCase):

    def test_bandit_parser_has_no_finding(self):
        testfile = open("dojo/unittests/scans/bandit/no_vuln.json")
        parser = BanditParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_bandit_parser_has_one_finding(self):
        testfile = open("dojo/unittests/scans/bandit/one_vuln.json")
        parser = BanditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_bandit_parser_has_many_findings(self):
        testfile = open("dojo/unittests/scans/bandit/many_vulns.json")
        parser = BanditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(213, len(findings))
        item = findings[0]
        self.assertEqual("Try, Except, Pass detected.", item.title)
        self.assertEqual(datetime.datetime(2020, 12, 30, 9, 35, 48, tzinfo=tzlocal()), item.date)
        self.assertEqual("Low", item.severity)
        self.assertEqual("dojo/benchmark\\views.py", item.file_path)
        self.assertEqual('try_except_pass:B110', item.vuln_id_from_tool)
        self.assertEqual("Certain", item.get_scanner_confidence_text())

    def test_bandit_parser_has_many_findings_recent(self):
        testfile = open("dojo/unittests/scans/bandit/dd.json")
        parser = BanditParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(47, len(findings))
        item = findings[0]
        self.assertEqual("Use of insecure MD2, MD4, MD5, or SHA1 hash function.", item.title)
        self.assertEqual(datetime.datetime(2021, 3, 30, 18, 23, 12, tzinfo=tzlocal()), item.date)
        self.assertEqual("Medium", item.severity)
        self.assertEqual("dojo/tools/acunetix/parser.py", item.file_path)
        self.assertEqual('blacklist:B303', item.vuln_id_from_tool)
        self.assertEqual("Certain", item.get_scanner_confidence_text())
