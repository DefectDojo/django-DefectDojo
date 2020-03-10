from django.test import TestCase
from dojo.tools.anchore_enterprise.parser import AnchoreEnterprisePolicyCheckParser, extract_cve
from dojo.models import Test


class TestAnchoreEnterprisePolicyCheckParser(TestCase):
    def test_anchore_policy_check_parser_has_no_findings(self):
        with open("dojo/unittests/scans/anchore_enterprise/no_checks.json") as testfile:
            parser = AnchoreEnterprisePolicyCheckParser(testfile, Test())
            self.assertEqual(0, len(parser.items))

    def test_anchore_policy_check_parser_has_one_finding(self):
        with open("dojo/unittests/scans/anchore_enterprise/one_check.json") as testfile:
            parser = AnchoreEnterprisePolicyCheckParser(testfile, Test())
            self.assertEqual(1, len(parser.items))

    def test_anchore_policy_check_parser_has_multiple_findings(self):
        with open("dojo/unittests/scans/anchore_enterprise/many_checks.json") as testfile:
            parser = AnchoreEnterprisePolicyCheckParser(testfile, Test())
            self.assertEqual(57, len(parser.items))

    def test_anchore_policy_check_parser_invalid_format(self):
        with open("dojo/unittests/scans/anchore_enterprise/invalid_checks_format.json") as testfile:
            with self.assertRaises(Exception):
                AnchoreEnterprisePolicyCheckParser(testfile, Test())

    def test_anchore_policy_check_extract_cve(self):
        cve = extract_cve("CVE-2019-14540+openapi-generator-cli-4.0.0.jar:jackson-databind")
        self.assertEqual("CVE-2019-14540", cve)
        cve = extract_cve("RHSA-2020:0227+sqlite")
        self.assertEqual("", cve)
        cve = extract_cve("41cb7cdf04850e33a11f80c42bf660b3")
        self.assertEqual("", cve)
        cve = extract_cve("")
        self.assertEqual("", cve)
