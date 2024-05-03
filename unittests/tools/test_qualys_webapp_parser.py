from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.qualys_webapp.parser import QualysWebAppParser
from dojo.models import Test


class TestQualysWebAppParser(DojoTestCase):

    def test_qualys_webapp_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/qualys_webapp/qualys_webapp_no_vuln.xml")
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 6 non-info findings, 17 total
        self.assertEqual(0, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(17, len(findings))

    def test_qualys_webapp_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("unittests/scans/qualys_webapp/qualys_webapp_one_vuln.xml")
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 8 non-info findings, 14 total
        self.assertEqual(1, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(14, len(findings))

    def test_qualys_webapp_parser_with_many_vuln_has_many_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/qualys_webapp/qualys_webapp_many_vuln.xml"
        )
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 3 non-info findings, 21 total
        self.assertEqual(3, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(21, len(findings))

    def test_qualys_webapp_parser_info_is_vuln(self):
        testfile = open(
            get_unit_tests_path() + "/scans/qualys_webapp/qualys_webapp_many_vuln.xml"
        )
        parser = QualysWebAppParser()
        findings = parser.get_findings(testfile, Test(), True)
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        # 18 non-info findings, 21 total
        self.assertEqual(18, len([x for x in findings if x.severity != "Info"]))
        self.assertEqual(21, len(findings))
