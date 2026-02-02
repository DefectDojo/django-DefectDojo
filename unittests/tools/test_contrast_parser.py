import datetime

from dojo.models import Engagement, Product, Test
from dojo.tools.contrast.parser import ContrastParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestContrastParser(DojoTestCase):

    def test_example_report(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with (get_unit_tests_scans_path("contrast") / "contrast-node-goat.csv").open(encoding="utf-8") as testfile:
            parser = ContrastParser()
            findings = parser.get_findings(testfile, test)
            self.validate_locations(findings)
            self.assertEqual(18, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Forms Without Autocomplete Prevention on 2 pages", finding.title)
                self.assertEqual("OMEC-Y0TI-FRLE-FJQQ", finding.unique_id_from_tool)
                self.assertEqual(522, finding.cwe)
                self.assertEqual(datetime.date(2018, 4, 23), finding.date.date())
                # endpoints
                self.assertIsNotNone(self.get_unsaved_locations(finding))
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("http", location.protocol)
                self.assertEqual("0.0.0.0", location.host)  # noqa: S104
                self.assertEqual("WebGoat/login.mvc", location.path)
            with self.subTest(i=11):
                finding = findings[11]
                self.assertEqual(datetime.date(2018, 4, 23), finding.date.date())
                self.assertEqual("High", finding.severity)
                self.assertEqual("path-traversal", finding.vuln_id_from_tool)
                self.assertIsNone(finding.unique_id_from_tool)  # aggregated finding
                self.assertEqual(4, finding.nb_occurences)
                self.assertEqual(22, finding.cwe)
                # endpoints
                self.assertIsNotNone(self.get_unsaved_locations(finding))
                self.assertEqual(4, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("http", location.protocol)
                self.assertEqual("0.0.0.0", location.host)  # noqa: S104
                self.assertEqual("WebGoat/services/SoapRequest", location.path)
                location = self.get_unsaved_locations(finding)[1]
                self.assertEqual("http", location.protocol)
                self.assertEqual("0.0.0.0", location.host)  # noqa: S104
                self.assertEqual("WebGoat/attack", location.path)

    def test_example2_report(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with (get_unit_tests_scans_path("contrast") / "vulnerabilities2020-09-21.csv").open(encoding="utf-8") as testfile:
            parser = ContrastParser()
            findings = parser.get_findings(testfile, test)
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual(datetime.date(2020, 5, 22), finding.date.date())
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("crypto-bad-mac", finding.vuln_id_from_tool)
                self.assertEqual("072U-8EYA-BNSH-PGN6", finding.unique_id_from_tool)
                self.assertEqual(327, finding.cwe)
                self.assertEqual(0, len(self.get_unsaved_locations(finding)))
