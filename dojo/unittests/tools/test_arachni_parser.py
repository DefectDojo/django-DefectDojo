
from django.test import TestCase
from dojo.tools.arachni.parser import ArachniParser
from dojo.models import Test


class TestAquaParser(TestCase):

    def test_aqua_parser_has_one_finding(self):
        with open("dojo/unittests/scans/arachni/arachni.afr.json") as testfile:
            parser = ArachniParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_aqua_parser_has_many_finding(self):
        with open("dojo/unittests/scans/arachni/dd.com.afr.json") as testfile:
            parser = ArachniParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("Missing 'Strict-Transport-Security' header", finding.title)
            self.assertEqual(200, finding.cwe)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual('demo.defectdojo.org', endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual('https', endpoint.protocol)
            # finding 2
            finding = findings[2]
            self.assertEqual("Interesting response", finding.title)
            self.assertIsNone(finding.cwe)
            self.assertIn('interesting', finding.unsaved_tags)
            self.assertIn('response', finding.unsaved_tags)
            self.assertIn('server', finding.unsaved_tags)

    def test_aqua_parser_has_many_finding2(self):
        with open("dojo/unittests/scans/arachni/js.com.afr.json") as testfile:
            parser = ArachniParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(10, len(findings))
            # finding 0
            finding = findings[0]
            self.assertEqual("SQL Injection", finding.title)
            self.assertEqual(89, finding.cwe)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual('juice-shop.herokuapp.com', endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual('https', endpoint.protocol)
            # finding 9
            finding = findings[9]
            self.assertEqual("Interesting response", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertIsNone(finding.cwe)
            self.assertEqual(25, finding.nb_occurences)
            self.assertEqual(25, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual('juice-shop.herokuapp.com', endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual('https', endpoint.protocol)
