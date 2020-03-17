from django.test import TestCase
from dojo.tools.anchore_enterprise.parser import AnchoreEnterprisePolicyCheckParser
from dojo.tools.anchore_enterprise.parser import extract_cve, search_filepath
from dojo.models import Test

# pylint: disable=C0103,C0301


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

    def test_anchore_policy_check_parser_search_filepath(self):
        file_path = search_filepath("MEDIUM Vulnerability found in non-os package type (python) - /usr/lib64/python2.7/lib-dynload/Python (CVE-2014-4616 - https://nvd.nist.gov/vuln/detail/CVE-2014-4616)")
        self.assertEqual('/usr/lib64/python2.7/lib-dynload/Python', file_path)
        file_path = search_filepath("HIGH Vulnerability found in non-os package type (java) - /root/.m2/repository/org/apache/struts/struts-core/1.3.8/struts-core-1.3.8.jar (CVE-2015-0899 - https://nvd.nist.gov/vuln/detail/CVE-2015-0899)")
        self.assertEqual('/root/.m2/repository/org/apache/struts/struts-core/1.3.8/struts-core-1.3.8.jar', file_path)
        file_path = search_filepath("test /usr/local/bin/ag package type (java) - /root/.m2/repository/org/apache/struts/struts-core/1.3.8/struts-core-1.3.8.jar (CVE-2015-0899 - https://nvd.nist.gov/vuln/detail/CVE-2015-0899)")
        self.assertEqual('/usr/local/bin/ag', file_path)
        file_path = search_filepath("HIGH Vulnerability found in os package type (rpm) - kernel-headers (RHSA-2017:0372 - https://access.redhat.com/errata/RHSA-2017:0372)")
        self.assertEqual('', file_path)
        file_path = search_filepath("test")
        self.assertEqual('', file_path)
