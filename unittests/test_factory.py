from dojo.tools.factory import get_parser
from dojo.models import Test, Test_Type
from .dojo_test_case import DojoTestCase, get_unit_tests_path


class TestFactory(DojoTestCase):
    def test_get_parser(self):
        with self.subTest(scan_type="Acunetix Scan"):
            scan_type = "Acunetix Scan"
            testfile = open(get_unit_tests_path() + "/scans/acunetix/one_finding.xml")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="Anchore Engine Scan"):
            scan_type = "Anchore Engine Scan"
            testfile = open(get_unit_tests_path() + "/scans/anchore/one_vuln.json")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="Nessus Scan"):
            scan_type = "Nessus Scan"
            testfile = open(get_unit_tests_path() + "/scans/nessus/nessus_v_unknown.xml")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()
        with self.subTest(scan_type="ZAP Scan"):
            scan_type = "ZAP Scan"
            testfile = open(get_unit_tests_path() + "/scans/zap/some_2.9.0.xml")
            parser = get_parser(scan_type)
            findings = parser.get_findings(testfile, Test())
            testfile.close()

    def test_get_parser_error(self):
        with self.assertRaises(ValueError):
            scan_type = "type_that_doesn't_exist"
            get_parser(scan_type)

    def test_get_parser_test_active_in_db(self):
        """This test is designed to validate that the factory take into account the falg 'active' in DB"""
        scan_type = "ZAP Scan"
        # desactivate the parser
        Test_Type.objects.update_or_create(
            name=scan_type,
            defaults={"active": False},
        )
        with self.assertRaises(ValueError):
            get_parser(scan_type)
        # activate the parser
        test_type, created = Test_Type.objects.update_or_create(
            name=scan_type,
            defaults={"active": True},
        )
        parser = get_parser(scan_type)
        self.assertIsNotNone(parser)
