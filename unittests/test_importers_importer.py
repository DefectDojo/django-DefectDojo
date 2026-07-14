import logging
import uuid
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
    Vulnerability_Id,
)
from dojo.tools.gitlab_sast.parser import GitlabSastParser
from dojo.tools.sarif.parser import SarifParser
from dojo.utils import get_object_or_none

from .dojo_test_case import DojoAPITestCase, DojoTestCase, get_unit_tests_path, get_unit_tests_scans_path
from .test_utils import assertImportModelsCreated

logger = logging.getLogger(__name__)

NPM_AUDIT_NO_VULN_FILENAME = get_unit_tests_scans_path("npm_audit") / "no_vuln.json"
NPM_AUDIT_SCAN_TYPE = "NPM Audit Scan"

ACUNETIX_AUDIT_ONE_VULN_FILENAME = get_unit_tests_scans_path("acunetix") / "one_finding.xml"
ENDPOINT_META_IMPORTER_FILENAME = get_unit_tests_path() / "endpoint_meta_import" / "no_endpoint_meta_import.csv"

ENGAGEMENT_NAME_DEFAULT = "Engagement 1"
ENGAGEMENT_NAME_NEW = "Engagement New 1"

PRODUCT_NAME_DEFAULT = "Product A"
PRODUCT_NAME_NEW = "Product New A"

PRODUCT_TYPE_NAME_DEFAULT = "Shiny Products"
PRODUCT_TYPE_NAME_NEW = "Extra Shiny Products"

TEST_TITLE_DEFAULT = "super important scan"
TEST_TITLE_ALTERNATE = "meh import scan"
TEST_TITLE_NEW = "lol importing via reimport"


class TestDojoDefaultImporter(DojoTestCase):
    def test_parse_findings(self):
        with (get_unit_tests_path() / "scans" / "acunetix" / "one_finding.xml").open(encoding="utf-8") as scan:
            scan_type = "Acunetix Scan"
            user, _created = User.objects.get_or_create(username="admin")
            product_type, _created = Product_Type.objects.get_or_create(name="test")
            product, _created = Product.objects.get_or_create(
                name="TestDojoDefaultImporter",
                description="test product",
                prod_type=product_type,
            )
            engagement, _created = Engagement.objects.get_or_create(
                name="Test Create Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            lead, _ = User.objects.get_or_create(username="admin")
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": lead,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "sync": True,
                "scan_type": scan_type,
                "engagement": engagement,
            }
            importer = DefaultImporter(**import_options)
            # create the test
            # by default test_type == scan_type
            test = importer.create_test(scan_type)
            # parse the findings
            parser = importer.get_parser()
            parsed_findings = parser.get_findings(scan, test)
            # process
            new_findings = importer.process_findings(parsed_findings)
            for finding in new_findings:
                self.assertIn(finding.numerical_severity, ["S0", "S1", "S2", "S3", "S4"])

    def test_import_scan(self):
        with (get_unit_tests_path() / "scans" / "sarif" / "spotbugs.sarif").open(encoding="utf-8") as scan:
            scan_type = SarifParser().get_scan_types()[0]  # SARIF format implement the new method
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test2")
            product, _ = Product.objects.get_or_create(
                name="TestDojoDefaultImporter2",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Create Engagement2",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            importer = DefaultImporter(**import_options)
            test, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(scan)
            self.assertEqual(f"SpotBugs Scan ({scan_type})", test.test_type.name)
            self.assertEqual(56, len_new_findings)
            self.assertEqual(0, len_closed_findings)

    def test_import_scan_without_test_scan_type(self):
        with (get_unit_tests_scans_path("gitlab_sast") / "gl-sast-report-1-vuln_v15.json").open(encoding="utf-8") as scan:
            # GitLabSastParser implements get_tests but report has no scanner name
            scan_type = GitlabSastParser().get_scan_types()[0]
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test2")
            product, _ = Product.objects.get_or_create(
                name="TestDojoDefaultImporter2",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Create Engagement2",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            importer = DefaultImporter(**import_options)
            test, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(scan)
            self.assertEqual("GitLab SAST Report", test.test_type.name)
            self.assertEqual(1, len_new_findings)
            self.assertEqual(0, len_closed_findings)

    def test_import_generic_with_custom_test_type(self):
        """Test Case 4: Initial import (should not trigger validation, should create new test)"""
        generic_test_type_1 = get_unit_tests_scans_path("generic") / "generic_test_type_1.json"
        with generic_test_type_1.open(encoding="utf-8") as scan:
            scan_type = "Generic Findings Import"
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test_generic")
            product, _ = Product.objects.get_or_create(
                name="TestGenericImporter",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Generic Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            importer = DefaultImporter(**import_options)
            test, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(scan)
            # Verify test is created successfully
            self.assertIsNotNone(test)
            # Verify test_type is set correctly based on report's type field
            self.assertEqual("Tool1 Scan (Generic Findings Import)", test.test_type.name)
            self.assertEqual(1, len_new_findings)
            self.assertEqual(0, len_closed_findings)

    def test_reimport_generic_with_matching_test_type(self):
        """Test Case 1: Reimport with matching test_type (should succeed)"""
        generic_test_type_1 = get_unit_tests_scans_path("generic") / "generic_test_type_1.json"
        with generic_test_type_1.open(encoding="utf-8") as scan:
            scan_type = "Generic Findings Import"
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test_generic_reimport")
            product, _ = Product.objects.get_or_create(
                name="TestGenericReimport",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Generic Reimport Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            # Initial import
            importer = DefaultImporter(**import_options)
            test, _, _, _, _, _, _ = importer.process_scan(scan)
            original_test_type_name = test.test_type.name
            self.assertEqual("Tool1 Scan (Generic Findings Import)", original_test_type_name)

            # Reimport with same test_type
            reimport_options = {
                "test": test,
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "close_old_findings": False,
            }
            reimporter = DefaultReImporter(**reimport_options)
            # Reset file pointer for reimport
            scan.seek(0)
            test_after_reimport, _, _, _, _, _, _ = reimporter.process_scan(scan)
            # Verify reimport succeeds without ValidationError
            self.assertEqual(test.id, test_after_reimport.id)
            # Verify test_type remains unchanged
            test.refresh_from_db()
            self.assertEqual(original_test_type_name, test.test_type.name)

    def test_reimport_generic_with_different_test_type(self):
        """Test Case 2: Reimport with different test_type (should fail with ValidationError)"""
        generic_test_type_1 = get_unit_tests_scans_path("generic") / "generic_test_type_1.json"
        generic_test_type_2 = get_unit_tests_scans_path("generic") / "generic_test_type_2.json"
        with generic_test_type_1.open(encoding="utf-8") as scan:
            scan_type = "Generic Findings Import"
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test_generic_mismatch")
            product, _ = Product.objects.get_or_create(
                name="TestGenericMismatch",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Generic Mismatch Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            # Initial import with Tool1
            importer = DefaultImporter(**import_options)
            test, _, _, _, _, _, _ = importer.process_scan(scan)
            original_test_type_name = test.test_type.name
            self.assertEqual("Tool1 Scan (Generic Findings Import)", original_test_type_name)
            original_finding_count = test.finding_set.count()

            # Attempt to reimport with Tool2 (different test_type)
            reimport_options = {
                "test": test,
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "close_old_findings": False,
            }
            reimporter = DefaultReImporter(**reimport_options)
            # Reset file pointer and use different file
            with generic_test_type_2.open(encoding="utf-8") as scan2:
                # Verify ValidationError is raised with appropriate message
                with self.assertRaises(ValidationError) as context:
                    reimporter.process_scan(scan2)
                error_message = str(context.exception)
                self.assertIn("Test type mismatch", error_message)
                self.assertIn("Tool1 Scan (Generic Findings Import)", error_message)
                self.assertIn("Tool2 Scan (Generic Findings Import)", error_message)
                self.assertIn(str(test.id), error_message)

            # Verify no findings are processed/updated
            test.refresh_from_db()
            self.assertEqual(original_finding_count, test.finding_set.count())
            # Verify test_type remains unchanged
            self.assertEqual(original_test_type_name, test.test_type.name)

    def test_reimport_generic_type_equals_scan_type(self):
        """Test reimport when type field equals scan_type (should succeed)"""
        generic_no_type = get_unit_tests_scans_path("generic") / "generic_no_type.json"
        generic_test_type_equals_scan_type = get_unit_tests_scans_path("generic") / "generic_test_type_equals_scan_type.json"
        with generic_no_type.open(encoding="utf-8") as scan:
            scan_type = "Generic Findings Import"
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test_generic_type_equals_scan_type")
            product, _ = Product.objects.get_or_create(
                name="TestGenericTypeEqualsScanType",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Generic Type Equals Scan Type Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            # Initial import without type field
            importer = DefaultImporter(**import_options)
            test, _, _, _, _, _, _ = importer.process_scan(scan)
            original_test_type_name = test.test_type.name
            # Should create test_type as just scan_type (no type field)
            self.assertEqual("Generic Findings Import", original_test_type_name)

            # Reimport with type field equal to scan_type
            reimport_options = {
                "test": test,
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "close_old_findings": False,
            }
            reimporter = DefaultReImporter(**reimport_options)
            # Use file with type field equal to scan_type
            with generic_test_type_equals_scan_type.open(encoding="utf-8") as scan2:
                # Should succeed without ValidationError
                test_after_reimport, _, len_new_findings, _, _, _, _ = reimporter.process_scan(scan2)
                # Verify reimport succeeds
                self.assertEqual(test.id, test_after_reimport.id)
                # Verify test_type remains unchanged (should still be "Generic Findings Import")
                test.refresh_from_db()
                self.assertEqual("Generic Findings Import", test.test_type.name)
                # Verify findings were processed
                self.assertGreater(len_new_findings, 0)

    # Regression: Generic import doubled the (Generic Findings Import) suffix in the Test_Type name
    def test_import_generic_type_with_suffix_is_not_doubled(self):
        """When the report's type already carries the scan-type suffix, it must be used verbatim (no ' Scan (...)' re-append)."""
        generic_test_type_suffix = get_unit_tests_scans_path("generic") / "generic_test_type_suffix.json"
        with generic_test_type_suffix.open(encoding="utf-8") as scan:
            scan_type = "Generic Findings Import"
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test_generic_suffix")
            product, _ = Product.objects.get_or_create(
                name="TestGenericSuffix",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Generic Suffix Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            importer = DefaultImporter(**import_options)
            test, _, _, _, _, _, _ = importer.process_scan(scan)
            self.assertIsNotNone(test)
            # The suffix must NOT be doubled into "... (Generic Findings Import) Scan (Generic Findings Import)"
            self.assertEqual(
                "Prisma Cloud (Generic Findings Import)", test.test_type.name,
                msg=f"expected 'Prisma Cloud (Generic Findings Import)', persisted='{test.test_type.name}'",
            )

    # Regression: dynamic parsers whose scan_type already ends in " Scan" (Horusec, AWS Security
    # Hub, Rusty Hog, ...) must not be doubled into "Horusec Scan (Horusec Scan)".
    def test_import_scan_suffixed_dynamic_type_is_not_doubled(self):
        """A report type of "Horusec" under scan_type "Horusec Scan" must resolve to "Horusec Scan"."""
        horusec_scan = get_unit_tests_scans_path("horusec") / "issue_6258.json"
        with horusec_scan.open(encoding="utf-8") as scan:
            scan_type = "Horusec Scan"
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test_scan_suffix")
            product, _ = Product.objects.get_or_create(
                name="TestScanSuffix",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Scan Suffix Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            importer = DefaultImporter(**import_options)
            test, _, _, _, _, _, _ = importer.process_scan(scan)
            self.assertIsNotNone(test)
            # Must be the plain scan type, NOT "Horusec Scan (Horusec Scan)"
            self.assertEqual(
                "Horusec Scan", test.test_type.name,
                msg=f"expected 'Horusec Scan', persisted='{test.test_type.name}'",
            )

    # Regression: Generic import doubled the (Generic Findings Import) suffix in the Test_Type name
    def test_reimport_generic_type_with_suffix_is_idempotent(self):
        """Reimporting a report whose type carries the scan-type suffix must not raise and must keep the same test/type."""
        generic_test_type_suffix = get_unit_tests_scans_path("generic") / "generic_test_type_suffix.json"
        with generic_test_type_suffix.open(encoding="utf-8") as scan:
            scan_type = "Generic Findings Import"
            user, _ = User.objects.get_or_create(username="admin")
            product_type, _ = Product_Type.objects.get_or_create(name="test_generic_suffix_reimport")
            product, _ = Product.objects.get_or_create(
                name="TestGenericSuffixReimport",
                description="test product",
                prod_type=product_type,
            )
            engagement, _ = Engagement.objects.get_or_create(
                name="Test Generic Suffix Reimport Engagement",
                product=product,
                target_start=timezone.now(),
                target_end=timezone.now(),
            )
            environment, _ = Development_Environment.objects.get_or_create(name="Development")
            import_options = {
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "engagement": engagement,
                "close_old_findings": False,
            }
            importer = DefaultImporter(**import_options)
            test, _, _, _, _, _, _ = importer.process_scan(scan)
            original_test_type_name = test.test_type.name
            self.assertEqual("Prisma Cloud (Generic Findings Import)", original_test_type_name)

            reimport_options = {
                "test": test,
                "user": user,
                "lead": user,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": scan_type,
                "close_old_findings": False,
            }
            reimporter = DefaultReImporter(**reimport_options)
            scan.seek(0)
            test_after_reimport, _, _, _, _, _, _ = reimporter.process_scan(scan)
            self.assertEqual(test.id, test_after_reimport.id)
            test.refresh_from_db()
            self.assertEqual(original_test_type_name, test.test_type.name)

    # Regression: Generic import doubled the (Generic Findings Import) suffix in the Test_Type name
    def test_reimport_into_legacy_doubled_test_type_still_works(self):
        """Pre-patch data: a Test whose test_type has the old doubled name must still accept reimports."""
        generic_test_type_suffix = get_unit_tests_scans_path("generic") / "generic_test_type_suffix.json"
        scan_type = "Generic Findings Import"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="test_generic_legacy_doubled")
        product, _ = Product.objects.get_or_create(
            name="TestGenericLegacyDoubled",
            description="test product",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Test Generic Legacy Doubled Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        # Simulate a test created by the pre-patch code: test_type name has the doubled suffix
        legacy_doubled_name = "Prisma Cloud (Generic Findings Import) Scan (Generic Findings Import)"
        legacy_test_type, _ = Test_Type.objects.get_or_create(name=legacy_doubled_name)
        test = Test.objects.create(
            engagement=engagement,
            test_type=legacy_test_type,
            environment=environment,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        reimport_options = {
            "test": test,
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "minimum_severity": "Info",
            "active": True,
            "verified": True,
            "scan_type": scan_type,
            "close_old_findings": False,
        }
        reimporter = DefaultReImporter(**reimport_options)
        with generic_test_type_suffix.open(encoding="utf-8") as scan:
            # Must NOT raise "Test type mismatch" for pre-existing doubled-name test types
            test_after_reimport, _, len_new_findings, _, _, _, _ = reimporter.process_scan(scan)
        self.assertEqual(test.id, test_after_reimport.id)
        test.refresh_from_db()
        # Historical name is preserved (we do not rename existing data)
        self.assertEqual(legacy_doubled_name, test.test_type.name)
        self.assertGreater(len_new_findings, 0)


class FlexibleImportTestAPI(DojoAPITestCase):
    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        DojoAPITestCase.__init__(self, *args, **kwargs)
        # super(ImportReimportMixin, self).__init__(*args, **kwargs)
        # super(DojoAPITestCase, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)

    def setUp(self):
        testuser, _ = User.objects.get_or_create(username="admin", is_superuser=True)
        # testuser = User.objects.get(username='admin')
        token, _ = Token.objects.get_or_create(user=testuser)
        self.client = APIClient(raise_request_exception=True)
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.create_default_data()
        # self.url = reverse(self.viewname + '-list')

    def create_default_data(self):
        # creating is much faster compare to using a fixture
        logger.debug("creating default product + engagement")
        Development_Environment.objects.get_or_create(name="Development")
        self.product_type = self.create_product_type(PRODUCT_TYPE_NAME_DEFAULT)
        self.product = self.create_product(PRODUCT_NAME_DEFAULT)
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_DEFAULT, product=self.product)
        # engagement name is not unique by itself and not unique inside a product
        self.engagement_last = self.create_engagement(ENGAGEMENT_NAME_DEFAULT, product=self.product)

    def test_import_by_engagement_id(self):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, engagement=self.engagement.id, test_title=TEST_TITLE_DEFAULT)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, TEST_TITLE_DEFAULT)
            self.assertEqual(import0["engagement_id"], self.engagement.id)
            self.assertEqual(import0["product_id"], self.engagement.product.id)

    def test_import_by_product_name_exists_engagement_name_exists(self):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT)
            test_id = import0["test"]
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement_last)
            self.assertEqual(import0["engagement_id"], self.engagement_last.id)
            self.assertEqual(import0["product_id"], self.engagement_last.product.id)

    def test_import_by_product_name_exists_engagement_name_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    def test_import_by_product_name_exists_engagement_name_not_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0["engagement_id"]).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(import0["product_id"], self.engagement.product.id)

    def test_import_by_product_name_not_exists_engagement_name(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    @patch("dojo.jira.helper.get_jira_project")
    def test_import_by_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0["engagement_id"]).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).prod_type.name, PRODUCT_TYPE_NAME_DEFAULT)

        mock.assert_not_called()

    @patch("dojo.jira.helper.get_jira_project")
    def test_import_by_product_type_name_not_exists_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=1, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0["engagement_id"]).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).prod_type.name, PRODUCT_TYPE_NAME_NEW)
            self.assertEqual(get_object_or_none(Product_Type, id=import0["product_type_id"]).name, PRODUCT_TYPE_NAME_NEW)

        mock.assert_not_called()

    def test_endpoint_meta_import_by_product_name_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(ENDPOINT_META_IMPORTER_FILENAME, product=None, product_name=PRODUCT_NAME_DEFAULT, expected_http_status_code=201)

    def test_endpoint_meta_import_by_product_name_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            self.endpoint_meta_import_scan_with_params(ENDPOINT_META_IMPORTER_FILENAME, product=None, product_name=PRODUCT_NAME_NEW, expected_http_status_code=400)

    def test_import_with_invalid_parameters(self):
        with self.subTest("scan_date in the future"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True, scan_date="2222-01-01",
                expected_http_status_code=400)

        with self.subTest("no parameters"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, expected_http_status_code=400)
            self.assertEqual(import0, ["product_name parameter missing"])

        with self.subTest("no product data"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, engagement_name="what the bleep", expected_http_status_code=400)
            self.assertEqual(import0, ["product_name parameter missing"])

        with self.subTest("engagement_name missing"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_name="67283", expected_http_status_code=400)
            self.assertEqual(import0, ["engagement_name parameter missing"])

        with self.subTest("invalid product type"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name="valentijn", product_name="67283", engagement_name="valentijn", expected_http_status_code=400)
            self.assertEqual(import0, ['Product Type "valentijn" does not exist'])

        with self.subTest("invalid product"):
            # random product type to avoid collision with other tests
            another_product_type_name = str(uuid.uuid4())
            Product_Type.objects.create(name=another_product_type_name)
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name=another_product_type_name, product_name=PRODUCT_NAME_DEFAULT, engagement_name="valentijn", expected_http_status_code=400)
            self.assertEqual(import0, [(
                    "The fetched product has a conflict with the supplied product type name: "
                    f"existing product type name - {PRODUCT_TYPE_NAME_DEFAULT} vs "
                    f"supplied product type name - {another_product_type_name}"
            )])

        with self.subTest("invalid engagement"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=1254235, expected_http_status_code=400)
            self.assertEqual(import0, ['Engagement "1254235" does not exist'])

        with self.subTest("invalid engagement, but exists in another product"):
            # random product to avoid collision with other tests
            another_product_name = str(uuid.uuid4())
            self.product = self.create_product(another_product_name)
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, engagement=None,
                engagement_name=ENGAGEMENT_NAME_DEFAULT, product_name=another_product_name, expected_http_status_code=400)
            self.assertEqual(import0, [f'Engagement "Engagement 1" does not exist in Product "{another_product_name}"'])

        with self.subTest("invalid engagement not id"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement="bla bla", expected_http_status_code=400)
            self.assertEqual(import0, ["engagement must be an integer"])

        with self.subTest("autocreate product but no product type name"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, [f'Product "{PRODUCT_NAME_NEW}" does not exist and no product_type_name provided to create the new product in'])

        with self.subTest("autocreate engagement but no product_name"):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=None,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, ["product_name parameter missing"])


class FlexibleReimportTestAPI(DojoAPITestCase):
    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        DojoAPITestCase.__init__(self, *args, **kwargs)
        # super(ImportReimportMixin, self).__init__(*args, **kwargs)
        # super(DojoAPITestCase, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)

    def setUp(self):
        testuser, _ = User.objects.get_or_create(username="admin", is_superuser=True)
        # testuser = User.objects.get(username='admin')
        token, _ = Token.objects.get_or_create(user=testuser)
        self.client = APIClient(raise_request_exception=True)
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.create_default_data()
        # self.url = reverse(self.viewname + '-list')

    def create_default_data(self):
        # creating is much faster compare to using a fixture
        logger.debug("creating default product + engagement")
        Development_Environment.objects.get_or_create(name="Development")
        self.product_type = self.create_product_type(PRODUCT_TYPE_NAME_DEFAULT)
        self.product = self.create_product(PRODUCT_NAME_DEFAULT)
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_DEFAULT, product=self.product)
        self.test = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_DEFAULT)
        # self.test = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE)
        # test title is not unique inside engagements
        self.test_last_by_title = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_DEFAULT)
        self.test_with_title = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_ALTERNATE)
        self.test_last_by_scan_type = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE)

    def test_reimport_by_test_id(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(self.test.id, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, TEST_TITLE_DEFAULT)
            self.assertEqual(test_id, self.test.id)
            self.assertEqual(import0["engagement_id"], self.test.engagement.id)
            self.assertEqual(import0["product_id"], self.test.engagement.product.id)

    def test_reimport_by_product_name_exists_engagement_name_exists_no_title(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT)
            test_id = import0["test"]
            self.assertEqual(test_id, self.test_last_by_scan_type.id)
            self.assertEqual(import0["engagement_id"], self.test_last_by_scan_type.engagement.id)
            self.assertEqual(import0["product_id"], self.test_last_by_scan_type.engagement.product.id)

    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type="Acunetix Scan", product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title=TEST_TITLE_DEFAULT, expected_http_status_code=400)

    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=1):
            import0 = self.reimport_scan_with_params(None, ACUNETIX_AUDIT_ONE_VULN_FILENAME, scan_type="Acunetix Scan", product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title=TEST_TITLE_DEFAULT, auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, TEST_TITLE_DEFAULT)
            self.assertEqual(import0["engagement_id"], self.engagement.id)

    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type="Acunetix Scan", product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title="bogus title", expected_http_status_code=400)

    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_not_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=1):
            import0 = self.reimport_scan_with_params(None, ACUNETIX_AUDIT_ONE_VULN_FILENAME, scan_type="Acunetix Scan", product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title="bogus title", auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).scan_type, "Acunetix Scan")
            self.assertEqual(get_object_or_none(Test, id=test_id).title, "bogus title")
            self.assertEqual(import0["engagement_id"], self.engagement.id)

    def test_reimport_by_product_name_exists_engagement_name_exists_test_title_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title=TEST_TITLE_DEFAULT)
            test_id = import0["test"]
            self.assertEqual(test_id, self.test_last_by_title.id)

    def test_reimport_by_product_name_exists_engagement_name_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    def test_reimport_by_product_name_exists_engagement_name_not_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0["engagement_id"]).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(import0["product_id"], self.engagement.product.id)
            self.assertEqual(import0["product_type_id"], self.engagement.product.prod_type.id)

    def test_reimport_by_product_name_not_exists_engagement_name(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    @patch("dojo.jira.helper.get_jira_project")
    def test_reimport_by_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0["engagement_id"]).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).prod_type.name, PRODUCT_TYPE_NAME_DEFAULT)

        mock.assert_not_called()

    @patch("dojo.jira.helper.get_jira_project")
    def test_reimport_by_product_type_not_exists_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=1, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True)
            test_id = import0["test"]
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0["engagement_id"]).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0["product_id"]).prod_type.name, PRODUCT_TYPE_NAME_NEW)

        mock.assert_not_called()

    def test_reimport_with_invalid_parameters(self):
        with self.subTest("scan_date in the future"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True, scan_date="2222-01-01",
                expected_http_status_code=400)

        with self.subTest("no parameters"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, expected_http_status_code=400)
            self.assertEqual(import0, ["product_name parameter missing"])

        with self.subTest("no product data"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, engagement_name="what the bleep", expected_http_status_code=400)
            self.assertEqual(import0, ["product_name parameter missing"])

        with self.subTest("non engagement_name"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_name="67283", expected_http_status_code=400)
            self.assertEqual(import0, ["engagement_name parameter missing"])

        with self.subTest("invalid product type"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name="valentijn", product_name="67283", engagement_name="valentijn", expected_http_status_code=400)
            self.assertEqual(import0, ['Product Type "valentijn" does not exist'])

        with self.subTest("invalid product"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_name="67283", engagement_name="valentijn", expected_http_status_code=400)
            self.assertEqual(import0, ['Product "67283" does not exist'])

        with self.subTest("valid product, but other product type"):
            # random product type to avoid collision with other tests
            another_product_type_name = str(uuid.uuid4())
            Product_Type.objects.create(name=another_product_type_name)

            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name=another_product_type_name, product_name=PRODUCT_NAME_DEFAULT, engagement_name="valentijn", expected_http_status_code=400)
            self.assertEqual(import0, [(
                    "The fetched product has a conflict with the supplied product type name: "
                    f"existing product type name - {PRODUCT_TYPE_NAME_DEFAULT} vs "
                    f"supplied product type name - {another_product_type_name}"
            )])

        with self.subTest("invalid engagement"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=1254235, expected_http_status_code=400)
            self.assertEqual(import0, ["product_name parameter missing"])

        with self.subTest("invalid engagement, but exists in another product"):
            # random product to avoid collision with other tests
            another_product_name = str(uuid.uuid4())
            self.product = self.create_product(another_product_name)
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement_name=ENGAGEMENT_NAME_DEFAULT, product_name=another_product_name, expected_http_status_code=400)
            self.assertEqual(import0, [f'Engagement "Engagement 1" does not exist in Product "{another_product_name}"'])

        with self.subTest("invalid engagement not id"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement="bla bla", expected_http_status_code=400)
            self.assertEqual(import0, ["engagement must be an integer"])

        with self.subTest("autocreate product but no product type name"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                product_name=PRODUCT_NAME_NEW, engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, [f'Product "{PRODUCT_NAME_NEW}" does not exist and no product_type_name provided to create the new product in'])

        with self.subTest("autocreate engagement but no product_name"):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, ["product_name parameter missing"])


class TestImporterUtils(DojoAPITestCase):
    def setUp(self):
        self.testuser, _ = User.objects.get_or_create(username="admin", is_superuser=True)
        token, _ = Token.objects.get_or_create(user=self.testuser)
        self.client = APIClient(raise_request_exception=True)
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.client.force_authenticate(user=self.testuser, token=token)
        self.create_default_data()

    def tearDown(self):
        self.test_last_by_scan_type.delete()
        self.test_with_title.delete()
        self.test_last_by_title.delete()
        self.test.delete()
        self.engagement.delete()
        self.product.delete()
        self.product_type.delete()
        self.testuser.delete()

    def create_default_data(self):
        # creating is much faster compare to using a fixture
        logger.debug("creating default product + engagement")
        Development_Environment.objects.get_or_create(name="Development")
        self.product_type = self.create_product_type(PRODUCT_TYPE_NAME_DEFAULT)
        self.product = self.create_product(PRODUCT_NAME_DEFAULT)
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_DEFAULT, product=self.product)
        self.test = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_DEFAULT)
        self.test_last_by_title = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_DEFAULT)
        self.test_with_title = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_ALTERNATE)
        self.test_last_by_scan_type = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE)
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.importer_data = {
            "engagement": self.engagement,
            "environment": environment,
            "scan_type": NPM_AUDIT_SCAN_TYPE,
        }

    def test_handle_vulnerability_ids_references_and_cve(self):
        vulnerability_ids = ["CVE", "REF-1", "REF-2"]
        finding = Finding()
        finding.unsaved_vulnerability_ids = vulnerability_ids
        finding.test = self.test
        finding.reporter = self.testuser
        finding.save()
        importer = DefaultImporter(**self.importer_data)
        importer.store_vulnerability_ids(finding)
        importer.flush_vulnerability_ids()

        self.assertEqual("CVE", finding.vulnerability_ids[0])
        self.assertEqual("CVE", finding.cve)
        self.assertEqual(vulnerability_ids, finding.unsaved_vulnerability_ids)
        self.assertEqual("REF-1", finding.vulnerability_ids[1])
        self.assertEqual("REF-2", finding.vulnerability_ids[2])
        finding.delete()

    def test_handle_no_vulnerability_ids_references_and_cve(self):
        vulnerability_ids = ["CVE"]
        finding = Finding()
        finding.test = self.test
        finding.reporter = self.testuser
        finding.save()
        finding.unsaved_vulnerability_ids = vulnerability_ids

        importer = DefaultImporter(**self.importer_data)
        importer.store_vulnerability_ids(finding)
        importer.flush_vulnerability_ids()

        self.assertEqual("CVE", finding.vulnerability_ids[0])
        self.assertEqual("CVE", finding.cve)
        self.assertEqual(vulnerability_ids, finding.unsaved_vulnerability_ids)
        finding.delete()

    def test_handle_vulnerability_ids_references_and_no_cve(self):
        vulnerability_ids = ["REF-1", "REF-2"]
        finding = Finding()
        finding.test = self.test
        finding.reporter = self.testuser
        finding.save()
        finding.unsaved_vulnerability_ids = vulnerability_ids
        importer = DefaultImporter(**self.importer_data)
        importer.store_vulnerability_ids(finding)
        importer.flush_vulnerability_ids()

        self.assertEqual("REF-1", finding.vulnerability_ids[0])
        self.assertEqual("REF-1", finding.cve)
        self.assertEqual(vulnerability_ids, finding.unsaved_vulnerability_ids)
        self.assertEqual("REF-2", finding.vulnerability_ids[1])
        finding.delete()

    def test_no_handle_vulnerability_ids_references_and_no_cve(self):
        finding = Finding()
        finding.test = self.test
        finding.reporter = self.testuser
        finding.save()
        importer = DefaultImporter(**self.importer_data)
        importer.store_vulnerability_ids(finding)
        importer.flush_vulnerability_ids()
        self.assertEqual(finding.cve, None)
        self.assertEqual(finding.unsaved_vulnerability_ids, None)
        self.assertEqual(finding.vulnerability_ids, [])
        finding.delete()

    def test_clear_vulnerability_ids_on_empty_list(self):
        """Test that vulnerability IDs are cleared when an empty list is provided"""
        # Create a finding with existing vulnerability IDs
        finding = Finding()
        finding.test = self.test
        finding.reporter = self.testuser
        finding.save()

        # Add some vulnerability IDs
        Vulnerability_Id.objects.create(finding=finding, vulnerability_id="CVE-2020-1234")
        Vulnerability_Id.objects.create(finding=finding, vulnerability_id="CVE-2020-5678")
        finding.cve = "CVE-2020-1234"
        finding.save()

        # Verify initial state
        self.assertEqual(2, len(finding.vulnerability_ids))
        self.assertEqual("CVE-2020-1234", finding.cve)

        # Process with empty list - should clear all IDs
        finding.unsaved_vulnerability_ids = []
        reimporter = DefaultReImporter(test=self.test, environment=self.importer_data["environment"], scan_type=self.importer_data["scan_type"])
        reimporter.reconcile_vulnerability_ids(finding)
        reimporter.flush_vulnerability_ids()
        # Save the finding to persist the cve=None change
        finding.save()

        # Get fresh finding from database to avoid cached property issues
        finding = Finding.objects.get(pk=finding.pk)

        # Verify IDs are cleared
        self.assertEqual(0, len(finding.vulnerability_ids))
        self.assertEqual(None, finding.cve)
        # Verify no Vulnerability_Id objects exist for this finding
        self.assertEqual(0, Vulnerability_Id.objects.filter(finding=finding).count())
        finding.delete()

    def test_change_vulnerability_ids_on_reimport(self):
        """Test that vulnerability IDs are updated when different IDs are provided"""
        # Create a finding with existing vulnerability IDs
        finding = Finding()
        finding.test = self.test
        finding.reporter = self.testuser
        finding.save()

        # Add initial vulnerability IDs
        Vulnerability_Id.objects.create(finding=finding, vulnerability_id="CVE-2020-1234")
        Vulnerability_Id.objects.create(finding=finding, vulnerability_id="CVE-2020-5678")
        finding.cve = "CVE-2020-1234"
        finding.save()

        # Verify initial state
        self.assertEqual(2, len(finding.vulnerability_ids))
        self.assertEqual("CVE-2020-1234", finding.vulnerability_ids[0])
        self.assertEqual("CVE-2020-5678", finding.vulnerability_ids[1])
        self.assertEqual("CVE-2020-1234", finding.cve)

        # Process with different IDs - should replace old IDs
        new_vulnerability_ids = ["CVE-2021-9999", "GHSA-xxxx-yyyy"]
        finding.unsaved_vulnerability_ids = new_vulnerability_ids
        reimporter = DefaultReImporter(test=self.test, environment=self.importer_data["environment"], scan_type=self.importer_data["scan_type"])
        reimporter.reconcile_vulnerability_ids(finding)
        reimporter.flush_vulnerability_ids()
        # Save the finding to persist the cve change
        finding.save()

        # Get fresh finding from database to avoid cached property issues
        finding = Finding.objects.get(pk=finding.pk)

        # Verify old IDs are removed and new IDs are present
        self.assertEqual(2, len(finding.vulnerability_ids))
        self.assertEqual("CVE-2021-9999", finding.vulnerability_ids[0])
        self.assertEqual("GHSA-xxxx-yyyy", finding.vulnerability_ids[1])
        self.assertEqual("CVE-2021-9999", finding.cve)
        # Verify only new Vulnerability_Id objects exist
        vuln_ids = list(Vulnerability_Id.objects.filter(finding=finding).values_list("vulnerability_id", flat=True))
        self.assertEqual(set(new_vulnerability_ids), set(vuln_ids))
        finding.delete()

    def test_reconcile_vulnerability_ids_cross_finding_batch(self):
        """Multiple findings accumulated before flush — one delete+insert pair per changed finding."""
        reimporter = DefaultReImporter(test=self.test, environment=self.importer_data["environment"], scan_type=self.importer_data["scan_type"])

        # finding_a: IDs change (CVE-A → CVE-B)
        finding_a = Finding(test=self.test, reporter=self.testuser)
        finding_a.save()
        Vulnerability_Id.objects.create(finding=finding_a, vulnerability_id="CVE-A-OLD")
        finding_a.cve = "CVE-A-OLD"
        finding_a.save()

        # finding_b: IDs change (CVE-B1, CVE-B2 → CVE-B-NEW)
        finding_b = Finding(test=self.test, reporter=self.testuser)
        finding_b.save()
        Vulnerability_Id.objects.create(finding=finding_b, vulnerability_id="CVE-B1")
        Vulnerability_Id.objects.create(finding=finding_b, vulnerability_id="CVE-B2")
        finding_b.cve = "CVE-B1"
        finding_b.save()

        # finding_c: IDs unchanged — should not appear in delete/insert buffers
        finding_c = Finding(test=self.test, reporter=self.testuser)
        finding_c.save()
        Vulnerability_Id.objects.create(finding=finding_c, vulnerability_id="CVE-C-SAME")
        finding_c.cve = "CVE-C-SAME"
        finding_c.save()

        finding_a.unsaved_vulnerability_ids = ["CVE-A-NEW"]
        finding_b.unsaved_vulnerability_ids = ["CVE-B-NEW"]
        finding_c.unsaved_vulnerability_ids = ["CVE-C-SAME"]

        # Accumulate all three before any flush
        reimporter.reconcile_vulnerability_ids(finding_a)
        reimporter.reconcile_vulnerability_ids(finding_b)
        reimporter.reconcile_vulnerability_ids(finding_c)

        # pending_vuln_id_deletes only contains changed findings, not finding_c
        self.assertIn(finding_a.id, reimporter.pending_vuln_id_deletes)
        self.assertIn(finding_b.id, reimporter.pending_vuln_id_deletes)
        self.assertNotIn(finding_c.id, reimporter.pending_vuln_id_deletes)
        self.assertEqual(2, len(reimporter.pending_vulnerability_ids))

        # Old IDs still in DB (not yet deleted)
        self.assertEqual(1, Vulnerability_Id.objects.filter(finding=finding_a).count())
        self.assertEqual(2, Vulnerability_Id.objects.filter(finding=finding_b).count())

        reimporter.flush_vulnerability_ids()

        # Buffers cleared
        self.assertEqual([], reimporter.pending_vuln_id_deletes)
        self.assertEqual([], reimporter.pending_vulnerability_ids)

        # finding_a: old deleted, new inserted
        vuln_ids_a = list(Vulnerability_Id.objects.filter(finding=finding_a).values_list("vulnerability_id", flat=True))
        self.assertEqual(["CVE-A-NEW"], vuln_ids_a)
        self.assertEqual("CVE-A-NEW", finding_a.cve)

        # finding_b: both old deleted, new inserted
        vuln_ids_b = list(Vulnerability_Id.objects.filter(finding=finding_b).values_list("vulnerability_id", flat=True))
        self.assertEqual(["CVE-B-NEW"], vuln_ids_b)
        self.assertEqual("CVE-B-NEW", finding_b.cve)

        # finding_c: unchanged — IDs untouched
        vuln_ids_c = list(Vulnerability_Id.objects.filter(finding=finding_c).values_list("vulnerability_id", flat=True))
        self.assertEqual(["CVE-C-SAME"], vuln_ids_c)

        finding_a.delete()
        finding_b.delete()
        finding_c.delete()

    def test_reconcile_vulnerability_ids_unchanged_no_db_write(self):
        """Early-exit path: unchanged IDs never touch pending buffers."""
        reimporter = DefaultReImporter(test=self.test, environment=self.importer_data["environment"], scan_type=self.importer_data["scan_type"])

        finding = Finding(test=self.test, reporter=self.testuser)
        finding.save()
        Vulnerability_Id.objects.create(finding=finding, vulnerability_id="CVE-2020-1234")
        finding.cve = "CVE-2020-1234"
        finding.save()

        finding.unsaved_vulnerability_ids = ["CVE-2020-1234"]
        reimporter.reconcile_vulnerability_ids(finding)

        self.assertEqual([], reimporter.pending_vuln_id_deletes)
        self.assertEqual([], reimporter.pending_vulnerability_ids)

        finding.delete()


class ReimportDuplicateReactivationTest(DojoTestCase):

    """
    Regression test for https://github.com/DefectDojo/django-DefectDojo/issues/14910

    Reimport reactivation of a mitigated finding must not produce an invalid
    active/verified duplicate finding state.
    """

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="admin", is_superuser=True)
        Development_Environment.objects.get_or_create(name="Development")
        self.product_type, _ = Product_Type.objects.get_or_create(name="dup_reactivation_pt")
        self.product, _ = Product.objects.get_or_create(
            name="DupReactivationProduct",
            description="test product",
            prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name="Dup Reactivation Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title="dup reactivation test")

    def _make_finding(self, title, **kwargs):
        return Finding.objects.create(
            title=title,
            test=self.test,
            severity="High",
            reporter=self.user,
            **kwargs,
        )

    def test_reactivation_keeps_duplicate_inactive_and_unverified(self):
        # Original active finding
        original = self._make_finding("original finding", active=True, verified=True)
        # Mitigated finding that is marked as a duplicate of the original
        existing_duplicate = self._make_finding(
            "duplicate finding",
            active=False,
            verified=False,
            duplicate=True,
            duplicate_finding=original,
            is_mitigated=True,
            mitigated=timezone.now(),
            mitigated_by=self.user,
        )
        # The reimported (unsaved) finding that re-matches the duplicate, and is active/not mitigated
        unsaved_finding = self._make_finding("duplicate finding incoming", active=True, verified=True)

        reimporter = DefaultReImporter(
            test=self.test,
            user=self.user,
            scan_type=NPM_AUDIT_SCAN_TYPE,
            active=True,
            verified=True,
            do_not_reactivate=False,
        )
        # These accumulators are normally initialised inside process_findings(); set them
        # here because the test drives process_matched_mitigated_finding() directly.
        reimporter.new_items = []
        reimporter.reactivated_items = []
        reimporter.unchanged_items = []

        result_finding, _ = reimporter.process_matched_mitigated_finding(unsaved_finding, existing_duplicate)

        result_finding.refresh_from_db()
        # The mitigation is cleared (the finding reappeared in the scan)...
        self.assertFalse(result_finding.is_mitigated)
        self.assertIsNone(result_finding.mitigated)
        # ...but a duplicate must never become active or verified (issue #14910)
        self.assertTrue(result_finding.duplicate)
        self.assertFalse(result_finding.active)
        self.assertFalse(result_finding.verified)

    def test_reactivation_of_non_duplicate_still_activates(self):
        # A regular mitigated finding (not a duplicate) must still reactivate as before
        existing = self._make_finding(
            "regular finding",
            active=False,
            verified=False,
            is_mitigated=True,
            mitigated=timezone.now(),
            mitigated_by=self.user,
        )
        unsaved_finding = self._make_finding("regular finding incoming", active=True, verified=True)

        reimporter = DefaultReImporter(
            test=self.test,
            user=self.user,
            scan_type=NPM_AUDIT_SCAN_TYPE,
            active=True,
            verified=True,
            do_not_reactivate=False,
        )
        # These accumulators are normally initialised inside process_findings(); set them
        # here because the test drives process_matched_mitigated_finding() directly.
        reimporter.new_items = []
        reimporter.reactivated_items = []
        reimporter.unchanged_items = []

        result_finding, _ = reimporter.process_matched_mitigated_finding(unsaved_finding, existing)

        result_finding.refresh_from_db()
        self.assertFalse(result_finding.is_mitigated)
        self.assertIsNone(result_finding.mitigated)
        self.assertTrue(result_finding.active)
        self.assertTrue(result_finding.verified)


# Regression: the per-batch post-processing dispatch read the push_to_jira flag computed
# for the LAST finding of the batch and applied it to the entire batch. With finding
# groups enabled and push_to_jira=True, a mixed batch ending in a grouped finding
# suppressed the JIRA push for every ungrouped finding in the batch (and vice versa).
class TestDojoImporterBatchPushToJira(DojoTestCase):
    def _process_findings_with_groups(self, parsed_findings):
        """Run process_findings with push_to_jira + group_by and capture per-finding dispatch flags."""
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="batch_push")
        product, _ = Product.objects.get_or_create(
            name="TestDojoImporterBatchPushToJira",
            description="test product",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Batch Push To Jira",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.system_settings(enable_finding_groups=True)
        importer = DefaultImporter(
            user=user,
            lead=user,
            scan_date=None,
            environment=environment,
            minimum_severity="Info",
            active=True,
            verified=True,
            scan_type=scan_type,
            engagement=engagement,
            push_to_jira=True,
            group_by="component_name",
        )
        test = importer.create_test(scan_type)
        for finding in parsed_findings:
            finding.test = test
        with (
            patch("dojo.importers.default_importer.dojo_dispatch_task") as dispatch_mock,
            patch("dojo.importers.default_importer.jira_services.push"),
        ):
            new_findings = importer.process_findings(parsed_findings)
        # Map each dispatched finding id to the push_to_jira flag its batch was sent with
        flag_by_finding_id = {}
        for call in dispatch_mock.call_args_list:
            finding_ids = call.args[1]
            for finding_id in finding_ids:
                flag_by_finding_id[finding_id] = call.kwargs["push_to_jira"]
        findings_by_title = {finding.title: finding for finding in new_findings}
        return flag_by_finding_id, findings_by_title

    def test_batch_push_to_jira_last_finding_grouped(self):
        # Last finding of the batch is grouped -> its False flag must NOT leak onto the
        # ungrouped finding processed before it
        ungrouped = Finding(title="Ungrouped Finding", severity="Medium", description="no component")
        grouped = Finding(title="Grouped Finding", severity="Medium", description="has component", component_name="lib-a")
        flags, findings_by_title = self._process_findings_with_groups([ungrouped, grouped])
        grouped_db = findings_by_title["Grouped Finding"]
        ungrouped_db = findings_by_title["Ungrouped Finding"]
        self.assertFalse(
            flags[grouped_db.id],
            msg=f"grouped finding must not be pushed individually, dispatched with push_to_jira={flags[grouped_db.id]}",
        )
        self.assertTrue(
            flags[ungrouped_db.id],
            msg=f"ungrouped finding must be pushed individually, dispatched with push_to_jira={flags[ungrouped_db.id]}",
        )

    def test_batch_push_to_jira_last_finding_ungrouped(self):
        # Last finding of the batch is ungrouped -> its True flag must NOT leak onto the
        # grouped finding processed before it
        grouped = Finding(title="Grouped Finding 2", severity="Medium", description="has component", component_name="lib-b")
        ungrouped = Finding(title="Ungrouped Finding 2", severity="Medium", description="no component")
        flags, findings_by_title = self._process_findings_with_groups([grouped, ungrouped])
        grouped_db = findings_by_title["Grouped Finding 2"]
        ungrouped_db = findings_by_title["Ungrouped Finding 2"]
        self.assertFalse(
            flags[grouped_db.id],
            msg=f"grouped finding must not be pushed individually, dispatched with push_to_jira={flags[grouped_db.id]}",
        )
        self.assertTrue(
            flags[ungrouped_db.id],
            msg=f"ungrouped finding must be pushed individually, dispatched with push_to_jira={flags[ungrouped_db.id]}",
        )
