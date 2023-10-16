from ..dojo_test_case import DojoTestCase
from dojo.tools.openvas_xml.parser import OpenVASXMLParser
from dojo.models import Test, Engagement, Product


class TestOpenVASUploadXMLParser(DojoTestCase):

    def test_openvas_xml_no_vuln(self):
        with open("unittests/scans/openvas_xml/no_vuln.xml") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASXMLParser()
            findings = parser.get_findings(f, test)
            self.assertEqual(0, len(findings))

    def test_openvas_xml_one_vuln(self):
        with open("unittests/scans/openvas_xml/one_vuln.xml") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASXMLParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Mozilla Firefox Security Update (mfsa_2023-32_2023-36) - Windows_10.0.101.2_general/tcp", finding.title)
                self.assertEqual("Critical", finding.severity)

    def test_openvas_xml_many_vuln(self):
        with open("unittests/scans/openvas_xml/many_vuln.xml") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASXMLParser()
            findings = parser.get_findings(f, test)
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(44, len(findings))
