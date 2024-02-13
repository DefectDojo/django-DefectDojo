from datetime import datetime, date

from dojo.tools.hydra.parser import HydraParser
from dojo.models import Test, Finding
from unittests.dojo_test_case import DojoTestCase


class TestHydraParser(DojoTestCase):
    __test_datetime = datetime(2019, 3, 1, 14, 44, 22)

    def test_invalid_json_format(self):
        testfile = open("unittests/scans/hydra/invalid.json")
        parser = HydraParser()
        with self.assertRaises(ValueError):
            parser.get_findings(testfile, Test())

    def test_parser_ensures_data_is_for_hydra_before_parsing(self):
        testfile = open("unittests/scans/hydra/oddly_familiar_json_that_isnt_us.json")
        parser = HydraParser()
        with self.assertRaises(ValueError):
            parser.get_findings(testfile, Test())

    def test_hydra_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/hydra/hydra_report_no_finding.json")
        parser = HydraParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_hydra_parser_with_one_finding_has_one_finding(self):
        testfile = open("unittests/scans/hydra/hydra_report_one_finding.json")
        parser = HydraParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.__assertAllEndpointsAreClean(findings)
        self.assertEqual(1, len(findings))

        finding = findings[0]

        self.__assertFindingEquals(
            finding,
            self.__test_datetime,
            "127.0.0.1",
            "9999",
            "bill@example.com",
            "bill"
        )

    def test_hydra_parser_with_one_finding_and_missing_date_has_one_finding(self):
        testfile = open("unittests/scans/hydra/hydra_report_one_finding_missing_date.json")
        parser = HydraParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.__assertAllEndpointsAreClean(findings)
        self.assertEqual(1, len(findings))

        finding = findings[0]

        self.__assertFindingEquals(
            finding,
            date.today(),
            "127.0.0.1",
            "9999",
            "bill@example.com",
            "bill"
        )

    def test_hydra_parser_with_two_findings_with_one_incomplete_has_one_finding(self):
        testfile = open("unittests/scans/hydra/hydra_report_two_findings_with_one_incomplete.json")
        parser = HydraParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.__assertAllEndpointsAreClean(findings)
        self.assertEqual(1, len(findings))

        finding = findings[0]

        self.__assertFindingEquals(
            finding,
            self.__test_datetime,
            "127.0.0.1",
            "9999",
            "bill@example.com",
            "bill"
        )

    def test_hydra_parser_with_many_findings_has_many_findings(self):
        testfile = open("unittests/scans/hydra/hydra_report_many_finding.json")
        parser = HydraParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.__assertAllEndpointsAreClean(findings)
        self.assertEqual(3, len(findings))

        self.__assertFindingEquals(
            findings[0],
            self.__test_datetime,
            "127.0.0.1",
            "9999",
            "bill@example.com",
            "bill"
        )
        self.__assertFindingEquals(
            findings[1],
            self.__test_datetime,
            "192.168.0.1",
            "1234",
            "joe@example.com",
            "joe"
        )
        self.__assertFindingEquals(
            findings[2],
            self.__test_datetime,
            "something.bad.com",
            "4321",
            "jimmy@bad.com",
            "somesimplepassword"
        )

    def __assertFindingEquals(
            self,
            actual_finding: Finding,
            date: datetime,
            finding_url,
            finding_port,
            finding_username,
            finding_password
    ):
        self.assertEqual("Weak username / password combination found for " + finding_url, actual_finding.title)
        self.assertEqual(date, actual_finding.date)
        self.assertEqual("High", actual_finding.severity)
        self.assertEqual(finding_url + " on port " + finding_port + " is allowing logins with easy to guess username " + finding_username + " and password " + finding_password,
                         actual_finding.description)
        self.assertFalse(actual_finding.static_finding)
        self.assertTrue(actual_finding.dynamic_finding)
        # The following fields should be not be set from this parser.
        self.assertIsNone(actual_finding.unique_id_from_tool)
        self.assertEqual(actual_finding.unsaved_endpoints[0].host, finding_url)
        self.assertEqual(str(actual_finding.unsaved_endpoints[0].port), finding_port)

    def __assertAllEndpointsAreClean(self, findings):
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
