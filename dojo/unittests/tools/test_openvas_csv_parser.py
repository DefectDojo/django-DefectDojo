from django.test import TestCase
from dojo.tools.openvas_csv.parser import OpenVASCsvParser
from dojo.models import Test, Engagement, Product


class TestOpenVASUploadCsvParser(TestCase):

    def test_openvas_csv_parser_without_file_has_no_findings(self):
        with open("dojo/unittests/scans/openvas/report-e2759495-f26d-4089-9c56-12a10dc36c9c.csv") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASCsvParser()
            findings = parser.get_findings(f, test)
            self.assertEqual(1, len(findings))
            # finding
            self.assertEqual("SSH Weak Encryption Algorithms Supported", findings[0].title)
            self.assertEqual("Medium", findings[0].severity)
            # endpoints
            self.assertEqual(1, len(findings[0].unsaved_endpoints))
            # endpoint
            self.assertEqual("10.0.0.8", findings[0].unsaved_endpoints[0].host)
            self.assertEqual("tcp", findings[0].unsaved_endpoints[0].protocol)
            self.assertEqual(22, findings[0].unsaved_endpoints[0].port)
