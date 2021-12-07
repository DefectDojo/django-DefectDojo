import os.path
import datetime
from django.test import TestCase
from dojo.tools.trufflehog3.parser import TruffleHog3Parser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join("dojo/unittests/scans/trufflehog3", file_name)


class TestTruffleHog3Parser(TestCase):

    def test_many_vulns(self):
        test_file = open(sample_path("many_vulns.json"))
        parser = TruffleHog3Parser()
        findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(findings), 7)
        # {
        #     "date": "2018-05-28 03:24:03",
        #     "path": "fixtures/users.json",
        #     "branch": "origin/master",
        #     "commit": "Update users.json",
        #     "commitHash": "3e2d1f58bf2ee974fb1195373d8526876fd6348b",
        #     "reason": "High entropy",
        #     "stringsFound": [
        #     "+      \"password\": \"md5$c77N8n6nJPb1$3b35343aac5e46740f6e673521aa53dc\",",
        #     "-      \"password\": \"md5$oAKvI66ce0Xq$a5c1836db3d6dedff5deca630a358d8b\","
        #     ]
        # }
        finding = findings[0]
        self.assertEqual("High", finding.severity)
        self.assertEqual(798, finding.cwe)
        self.assertEqual('fixtures/users.json', finding.file_path)
        # FIXME for now the date in Finding is type datetime.date we need to switch to datetime
        # self.assertEqual(datetime.datetime, type(finding.date))
        # self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), finding.date)
        self.assertEqual(datetime.date, type(finding.date))
        self.assertEqual(7, finding.nb_occurences)

    def test_many_vulns2(self):
        test_file = open(sample_path("many_vulns2.json"))
        parser = TruffleHog3Parser()
        findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(findings), 27)
        finding = findings[0]
        self.assertEqual("High", finding.severity)
        self.assertEqual(798, finding.cwe)
        self.assertEqual('test_all.py', finding.file_path)
        self.assertEqual(8, finding.nb_occurences)
