from django.test import override_settings

from dojo.models import Test_Import, User

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path, versioned_fixtures


@versioned_fixtures
class ImportResponseTestImportIdTest(DojoAPITestCase):

    """
    The import-scan and reimport-scan responses name the Test_Import the request created.

    A client that wants the findings a single import touched (new, closed, reactivated,
    untouched) reads test_import_id from the response and fetches that record, rather
    than guessing at the newest Test_Import for the test, which a concurrent import to
    the same test can make wrong.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        self.zap_sample0 = get_unit_tests_scans_path("zap") / "0_zap_sample.xml"
        self.zap_sample1 = get_unit_tests_scans_path("zap") / "1_zap_sample_0_and_new_absent.xml"

    def test_import_returns_the_created_test_import(self):
        response = self.import_scan_with_params(self.zap_sample0)

        test_import = Test_Import.objects.get(id=response["test_import_id"])
        self.assertEqual(response["test_id"], test_import.test_id)
        self.assertEqual("import", test_import.type)

    def test_reimport_returns_the_created_test_import(self):
        imported = self.import_scan_with_params(self.zap_sample0)

        response = self.reimport_scan_with_params(imported["test_id"], self.zap_sample1)

        test_import = Test_Import.objects.get(id=response["test_import_id"])
        self.assertNotEqual(imported["test_import_id"], response["test_import_id"])
        self.assertEqual(imported["test_id"], test_import.test_id)
        self.assertEqual("reimport", test_import.type)

    def test_reimport_that_auto_creates_the_test_returns_its_test_import(self):
        response = self.reimport_scan_with_params(
            None,
            self.zap_sample0,
            engagement=None,
            engagement_name="Manifest Engagement",
            product_name="Manifest Product",
            product_type_name="Manifest Product Type",
            auto_create_context=True,
        )

        test_import = Test_Import.objects.get(id=response["test_import_id"])
        self.assertEqual(response["test_id"], test_import.test_id)
        self.assertEqual("import", test_import.type)

    @override_settings(TRACK_IMPORT_HISTORY=False)
    def test_import_history_off_returns_null(self):
        imported = self.import_scan_with_params(self.zap_sample0)
        reimported = self.reimport_scan_with_params(imported["test_id"], self.zap_sample1)

        self.assertIn("test_import_id", imported)
        self.assertIsNone(imported["test_import_id"])
        self.assertIn("test_import_id", reimported)
        self.assertIsNone(reimported["test_import_id"])
        self.assertFalse(Test_Import.objects.filter(test_id=imported["test_id"]).exists())
