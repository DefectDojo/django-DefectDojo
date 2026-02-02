from datetime import date

from dojo.models import Test
from dojo.tools.acunetix.parser import AcunetixParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAcunetixParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        with (get_unit_tests_scans_path("acunetix") / "one_finding_with_port_num.xml").open(encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(352, finding.cwe)
                self.assertEqual(date(2018, 9, 24), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertFalse(finding.false_p)
                self.assertEqual("Vijay Test Imapact", finding.impact)
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                # check endpoints
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("https", location.protocol)
                self.assertEqual(443, location.port)
                self.assertEqual("vijaytest.com", location.host)
                self.assertEqual("some/path", location.path)

    def test_parse_file_with_multiple_finding(self):
        with (get_unit_tests_scans_path("acunetix") / "many_findings_with_port_number.xml").open(encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(4, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(date(2020, 2, 27), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertEqual("A single machine can take down another machine's web server with minimal bandwidth and side effects on unrelated services and ports.", finding.impact)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertFalse(location.protocol)
                self.assertEqual(location.port, 8080)
                self.assertEqual("www.itsecgames.com", location.host)
                self.assertFalse(location.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Possible virtual host found", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual(200, finding.cwe)
                self.assertEqual(date(2020, 2, 27), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertEqual("Possible sensitive information disclosure.", finding.impact)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertFalse(location.protocol)
                self.assertEqual(location.port, 8080)
                self.assertEqual("www.itsecgames.com", location.host)
                self.assertFalse(location.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Unencrypted connection (verified)", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual(310, finding.cwe)
                self.assertEqual(date(2020, 2, 27), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertEqual("Possible information disclosure.", finding.impact)
                # check that this finding have no references
                self.assertIsNone(finding.references)
                # check endpoints
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertFalse(location.protocol)
                self.assertEqual(location.port, 8080)
                self.assertEqual("www.itsecgames.com", location.host)
                self.assertFalse(location.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)

    def test_parse_file_with_example_com(self):
        with (get_unit_tests_scans_path("acunetix") / "XML_http_example_co_id_port_num.xml").open(encoding="utf-8") as testfile:
            parser = AcunetixParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(7, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("HTML form without CSRF protection", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(date(2020, 4, 28), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", finding.cvssv3)
                self.assertFalse(finding.false_p)
                self.assertIn("An attacker could use CSRF to trick a victim into accessing a website hosted by the attacker,", finding.impact)
                # aggregated
                self.assertEqual(3, finding.nb_occurences)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(3, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertFalse(location.protocol)
                self.assertEqual(location.port, 9000)
                self.assertEqual("example.co.id", location.host)
                self.assertEqual("h/search", location.path)
                location = self.get_unsaved_locations(finding)[1]
                self.assertFalse(location.protocol)
                self.assertEqual(location.port, 9000)
                self.assertEqual("example.co.id", location.host)
                self.assertEqual("m/zmain", location.path)
                # check req/resp
                self.assertEqual(3, len(finding.unsaved_req_resp))
                for req_resp in finding.unsaved_req_resp:
                    self.assertIn("req", req_resp)
                    self.assertIsNotNone(req_resp["req"])
                    self.assertIsInstance(req_resp["req"], str)
                    self.assertIn("resp", req_resp)
                    self.assertIsNotNone(req_resp["resp"])
                    self.assertIsInstance(req_resp["resp"], str)

            with self.subTest(i=6):
                finding = findings[6]
                self.assertEqual("Content Security Policy (CSP) not implemented", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual(date(2020, 4, 28), finding.date)
                self.assertIsNotNone(finding.description)
                self.assertFalse(finding.false_p)
                self.assertIn("CSP can be used to prevent and/or mitigate attacks that involve content/code injection,", finding.impact)
                # check that this finding have references
                self.assertIsNotNone(finding.references)
                self.assertGreater(len(finding.references), 0)
                # check endpoints
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertFalse(location.protocol)
                self.assertEqual(location.port, 9000)
                self.assertEqual("example.co.id", location.host)
                self.assertFalse(location.path)
                # check req/resp
                self.assertEqual(1, len(finding.unsaved_req_resp))
                req_resp = finding.unsaved_req_resp[0]
                self.assertIn("req", req_resp)
                self.assertIsNotNone(req_resp["req"])
                self.assertIsInstance(req_resp["req"], str)
                self.assertIn("resp", req_resp)
                self.assertIsNotNone(req_resp["resp"])
                self.assertIsInstance(req_resp["resp"], str)
