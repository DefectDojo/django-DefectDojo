from unittests.dojo_test_case import DojoAPITestCase
import os

class XMLParseErrorTest(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.login_as_admin()

    def test_import_scan_malformed_xml_zap(self):
        """
        Test that importing a malformed XML file via the API returns a 400 error
        instead of crashing the worker (propagating ParseError).
        """
        # engagement 1 should exist from fixtures
        relative_path = os.path.join("scans", "zap", "malformed.xml")

        # We expect a 400 Bad Request if handled
        response = self.import_scan_with_params(
            filename=relative_path,
            scan_type="ZAP Scan",
            engagement=1,
            expected_http_status_code=400
        )
        
        self.assertIn("Malformed XML", response["file"][0])
