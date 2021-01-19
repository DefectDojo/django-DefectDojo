from django.test import TestCase
from dojo.tools.gitlab_sast.parser import GitlabSastReportParser
from dojo.models import Test


class TestGitlabSastReportParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = GitlabSastReportParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-0-vuln.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-1-vuln.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-many-vuln.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertTrue(len(parser.items) > 2)

    def test_parse_file_with_various_confidences(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-confidence.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertTrue(len(parser.items) == 8)
        i = 0
        for item in parser.items:
            self.assertTrue(item.cwe is None or isinstance(item.cwe, int))
            self.assertEqual(item.get_scanner_confidence_text(), get_confidence_defectdojo(i))
            i = i + 1

    def test_parse_file_with_various_cwes(self):
        testfile = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-cwe.json")
        parser = GitlabSastReportParser(testfile, Test())
        self.assertTrue(len(parser.items) == 3)
        self.assertEqual(79, parser.items[0].cwe)
        self.assertEqual(89, parser.items[1].cwe)
        self.assertEqual(None, parser.items[2].cwe)


def get_confidence_defectdojo(argument):
    switcher = {
        0: '',
        1: '',
        2: '',
        3: 'Tentative',
        4: 'Tentative',
        5: 'Firm',
        6: 'Firm',
        7: 'Certain'
    }
    return switcher.get(argument, None)
