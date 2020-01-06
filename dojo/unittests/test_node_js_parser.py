from django.test import TestCase
from dojo.tools.node_js.parser import NodeJSParser
from dojo.models import Test


class TestNodeJSParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_finding(self):
        testfile = open("dojo/unittests/scans/node_js/node_js_zero.json")
        parser = NodeJSParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_one_vuln_has_one_finding(self):
        testfile = open("dojo/unittests/scans/node_js/node_js_one.json")
        parser = NodeJSParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/node_js/node_js_many.json")
        parser = NodeJSParser(testfile, Test())
        self.assertEqual(5, len(parser.items))
