import datetime

from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.acunetix.parser import AcunetixParser


class TestAcunetixParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        testfile = open("unittests/scans/acunetix/one_finding.xml")
        parser = AcunetixParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(352, finding.cwe)
            self.assertEqual(datetime.date(2018, 9, 24), finding.date)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertFalse(finding.false_p)
            self.assertEqual("Vijay Test Imapact", finding.impact)
            self.assertIsNotNone(finding.references)
            self.assertGreater(len(finding.references), 0)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            # check endpoints
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual('https', endpoint.protocol)
            self.assertEqual(443, endpoint.port)
            self.assertEqual('vijaytest.com', endpoint.host)
            self.assertEqual('some/path', endpoint.path)

    def test_parse_file_with_multiple_finding(self):
        testfile = open("unittests/scans/acunetix/many_findings.xml")
        parser = AcunetixParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(4, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(datetime.date(2020, 2, 27), finding.date)
            self.assertIsNotNone(finding.description)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", finding.cvssv3)
            self.assertFalse(finding.false_p)
            self.assertEqual("A single machine can take down another machine's web server with minimal bandwidth and side effects on unrelated services and ports.", finding.impact)
            # check that this finding have references
            self.assertIsNotNone(finding.references)
            self.assertGreater(len(finding.references), 0)
            # check endpoints
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertIsNone(endpoint.protocol)
            self.assertIsNone(endpoint.port)
            self.assertEqual('www.itsecgames.com', endpoint.host)
            self.assertIsNone(endpoint.path)
            # check req/resp
            self.assertEqual(1, len(finding.unsaved_req_resp))
            req_resp = finding.unsaved_req_resp[0]
            self.assertIn('req', req_resp)
            self.assertIsNotNone(req_resp['req'])
            self.assertIsInstance(req_resp['req'], str)
            self.assertIn('resp', req_resp)
            self.assertIsNotNone(req_resp['resp'])
            self.assertIsInstance(req_resp['resp'], str)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("Possible virtual host found", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(200, finding.cwe)
            self.assertEqual(datetime.date(2020, 2, 27), finding.date)
            self.assertIsNotNone(finding.description)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", finding.cvssv3)
            self.assertFalse(finding.false_p)
            self.assertEqual("Possible sensitive information disclosure.", finding.impact)
            # check that this finding have references
            self.assertIsNotNone(finding.references)
            self.assertGreater(len(finding.references), 0)
            # check endpoints
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertIsNone(endpoint.protocol)
            self.assertIsNone(endpoint.port)
            self.assertEqual('www.itsecgames.com', endpoint.host)
            self.assertIsNone(endpoint.path)
            # check req/resp
            self.assertEqual(1, len(finding.unsaved_req_resp))
            req_resp = finding.unsaved_req_resp[0]
            self.assertIn('req', req_resp)
            self.assertIsNotNone(req_resp['req'])
            self.assertIsInstance(req_resp['req'], str)
            self.assertIn('resp', req_resp)
            self.assertIsNotNone(req_resp['resp'])
            self.assertIsInstance(req_resp['resp'], str)

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("Unencrypted connection (verified)", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(310, finding.cwe)
            self.assertEqual(datetime.date(2020, 2, 27), finding.date)
            self.assertIsNotNone(finding.description)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", finding.cvssv3)
            self.assertFalse(finding.false_p)
            self.assertEqual("Possible information disclosure.", finding.impact)
            # check that this finding have no references
            self.assertIsNone(finding.references)
            # check endpoints
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertIsNone(endpoint.protocol)
            self.assertIsNone(endpoint.port)
            self.assertEqual('www.itsecgames.com', endpoint.host)
            self.assertIsNone(endpoint.path)
            # check req/resp
            self.assertEqual(1, len(finding.unsaved_req_resp))
            req_resp = finding.unsaved_req_resp[0]
            self.assertIn('req', req_resp)
            self.assertIsNotNone(req_resp['req'])
            self.assertIsInstance(req_resp['req'], str)
            self.assertIn('resp', req_resp)
            self.assertIsNotNone(req_resp['resp'])
            self.assertIsInstance(req_resp['resp'], str)

    def test_parse_file_with_example_com(self):
        testfile = open("unittests/scans/acunetix/XML_http_example_co_id_.xml")
        parser = AcunetixParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(7, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("HTML form without CSRF protection", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(datetime.date(2020, 4, 28), finding.date)
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
            self.assertEqual(3, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertIsNone(endpoint.protocol)
            self.assertIsNone(endpoint.port)
            self.assertEqual('example.co.id', endpoint.host)
            self.assertEqual('h/search', endpoint.path)
            endpoint = finding.unsaved_endpoints[1]
            self.assertIsNone(endpoint.protocol)
            self.assertIsNone(endpoint.port)
            self.assertEqual('example.co.id', endpoint.host)
            self.assertEqual('m/zmain', endpoint.path)
            # check req/resp
            self.assertEqual(3, len(finding.unsaved_req_resp))
            for req_resp in finding.unsaved_req_resp:
                self.assertIn('req', req_resp)
                self.assertIsNotNone(req_resp['req'])
                self.assertIsInstance(req_resp['req'], str)
                self.assertIn('resp', req_resp)
                self.assertIsNotNone(req_resp['resp'])
                self.assertIsInstance(req_resp['resp'], str)

        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("Content Security Policy (CSP) not implemented", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(datetime.date(2020, 4, 28), finding.date)
            self.assertIsNotNone(finding.description)
            self.assertFalse(finding.false_p)
            self.assertIn("CSP can be used to prevent and/or mitigate attacks that involve content/code injection,", finding.impact)
            # check that this finding have references
            self.assertIsNotNone(finding.references)
            self.assertGreater(len(finding.references), 0)
            # check endpoints
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertIsNone(endpoint.protocol)
            self.assertIsNone(endpoint.port)
            self.assertEqual('example.co.id', endpoint.host)
            self.assertIsNone(endpoint.path)
            # check req/resp
            self.assertEqual(1, len(finding.unsaved_req_resp))
            req_resp = finding.unsaved_req_resp[0]
            self.assertIn('req', req_resp)
            self.assertIsNotNone(req_resp['req'])
            self.assertIsInstance(req_resp['req'], str)
            self.assertIn('resp', req_resp)
            self.assertIsNotNone(req_resp['resp'])
            self.assertIsInstance(req_resp['resp'], str)
