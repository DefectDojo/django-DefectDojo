import logging

from django.conf import settings
from django.contrib.contenttypes.models import ContentType

from dojo.location.models import Location, LocationFindingReference
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    User,
    UserContactInfo,
)
from dojo.url.models import URL

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

STACK_HAWK_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings.json"
STACK_HAWK_SUBSET_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings_subset.json"
STACK_HAWK_SCAN_TYPE = "StackHawk HawkScan"


class TestDojoImportersDeduplication(DojoAPITestCase):

    def setUp(self):
        super().setUp()

        testuser = User.objects.create(username="admin")
        testuser.is_superuser = True
        testuser.is_staff = True
        testuser.save()
        UserContactInfo.objects.create(user=testuser, block_execution=True)

        # Authenticate API client as admin for import endpoints
        self.login_as_admin()

        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_deduplication=True)

        # Warm up ContentType cache for relevant models. This is needed if we want to be able to run the test in isolation
        # As part of the test suite the ContentType ids will already be cached and won't affect the query count.
        # But if we run the test in isolation, the ContentType ids will not be cached and will result in more queries.
        # By warming up the cache here, these queries are executed before we start counting queries
        for model in self.get_models_for_contenttype_cache():
            ContentType.objects.get_for_model(model)

    def get_models_for_contenttype_cache(self):
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            return [Development_Environment, Dojo_User, Endpoint, Endpoint_Status, Engagement, Finding, Product, Product_Type, User, Test]
        return [Development_Environment, Dojo_User, Location, URL, LocationFindingReference, Engagement, Finding, Product, Product_Type, User, Test]

    # Internal helper methods for reusable test logic
    def _test_single_import_assess_duplicates(self, filename, scan_type, expected_duplicates):
        """Internal method to test single import with expected duplicates"""
        self.login_as_admin()

        response_json = self.import_scan_with_params(
            filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=f"PT {scan_type} Single",
            product_name=f"P {scan_type} Single",
            engagement_name=f"E {scan_type} Single",
            auto_create_context=True,
        )

        test_id = response_json["test"]
        test = Test.objects.get(id=test_id)

        # Verify expected duplicates were created
        dup_count = Finding.objects.filter(test=test, duplicate=True).count()
        self.assertEqual(expected_duplicates, dup_count)

        # Assess duplicate structure invariants
        self._assess_duplicates_in_test(test)

        return test_id

    def _test_full_then_subset_duplicates(self, full_filename, subset_filename, scan_type, expected_duplicates, first_import_duplicates=0):
        """
        Internal method to test full scan then subset creates expected duplicates

        Args:
            first_import_duplicates: Expected number of duplicates in the first import (for files with internal duplicates)

        """
        # First import: full scan
        response_json = self.import_scan_with_params(
            full_filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=f"PT {scan_type} Full",
            product_name=f"P {scan_type} Full",
            engagement_name=f"E {scan_type} Full",
            auto_create_context=True,
        )

        first_test_id = response_json["test"]
        first_test = Test.objects.get(id=first_test_id)

        # Verify first import has expected duplicates (usually 0, but may have internal duplicates)
        first_dup_count = Finding.objects.filter(test=first_test, duplicate=True).count()
        self.assertEqual(first_import_duplicates, first_dup_count)

        # Assess duplicate structure invariants on first import
        self._assess_duplicates_in_test(first_test)

        # Second import: subset into the same engagement
        response_json = self.import_scan_with_params(
            subset_filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=first_test.engagement.id,  # Same engagement ID
            product_type_name=None,  # Use existing
            product_name=None,  # Use existing
            engagement_name=None,  # Use existing
            auto_create_context=False,
        )

        second_test_id = response_json["test"]
        second_test = Test.objects.get(id=second_test_id)

        # The second test should contain expected duplicates
        second_test_dup_count = Finding.objects.filter(test=second_test, duplicate=True).count()
        self.assertEqual(expected_duplicates, second_test_dup_count)

        # Assess duplicate structure invariants on second import
        self._assess_duplicates_in_test(second_test)

        # Engagement should have total duplicates from both imports
        total_expected_duplicates = first_import_duplicates + expected_duplicates
        eng_dup_count = Finding.objects.filter(test__engagement=first_test.engagement, duplicate=True).count()
        self.assertEqual(total_expected_duplicates, eng_dup_count)

        # Product should have total duplicates from both imports
        prod_dup_count = Finding.objects.filter(test__engagement__product=first_test.engagement.product, duplicate=True).count()
        self.assertEqual(total_expected_duplicates, prod_dup_count)

        return second_test_id

    def _test_different_products_no_duplicates(self, filename, scan_type, expected_duplicates):
        """Internal method to test importing into different products creates expected duplicates"""
        # First import: into Product A
        response_json = self.import_scan_with_params(
            filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=f"PT {scan_type} Product A",
            product_name=f"P {scan_type} Product A",
            engagement_name=f"E {scan_type} Product A",
            auto_create_context=True,
        )

        first_test_id = response_json["test"]
        first_test = Test.objects.get(id=first_test_id)

        # Verify first import has expected duplicates
        first_dup_count = Finding.objects.filter(test=first_test, duplicate=True).count()
        self.assertEqual(expected_duplicates, first_dup_count)

        # Assess duplicate structure invariants
        self._assess_duplicates_in_test(first_test)

        # Second import: same scan into Product B (different product)
        response_json = self.import_scan_with_params(
            filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=f"PT {scan_type} Product B",
            product_name=f"P {scan_type} Product B",
            engagement_name=f"E {scan_type} Product B",
            auto_create_context=True,
        )

        second_test_id = response_json["test"]
        second_test = Test.objects.get(id=second_test_id)

        # The second test should contain expected duplicates (different products don't deduplicate)
        second_test_dup_count = Finding.objects.filter(test=second_test, duplicate=True).count()
        self.assertEqual(expected_duplicates, second_test_dup_count)

        # Assess duplicate structure invariants
        self._assess_duplicates_in_test(second_test)

        # First product should still have expected duplicates
        first_prod_dup_count = Finding.objects.filter(test__engagement__product=first_test.engagement.product, duplicate=True).count()
        self.assertEqual(expected_duplicates, first_prod_dup_count)

        # Second product should have expected duplicates
        second_prod_dup_count = Finding.objects.filter(test__engagement__product=second_test.engagement.product, duplicate=True).count()
        self.assertEqual(expected_duplicates, second_prod_dup_count)

        return second_test_id

    def _test_same_product_different_engagements_duplicates(self, filename, scan_type, expected_duplicates):
        """Internal method to test importing into same product but different engagements creates expected duplicates"""
        # First import: into Engagement 1
        response_json = self.import_scan_with_params(
            filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=f"PT {scan_type} SameProd",
            product_name=f"P {scan_type} SameProd",
            engagement_name=f"E {scan_type} SameProd 1",
            auto_create_context=True,
        )
        first_test = Test.objects.get(id=response_json["test"])

        # Second import: into Engagement 2 (same product)
        response_json = self.import_scan_with_params(
            filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=None,  # Use existing
            product_name=f"P {scan_type} SameProd",  # Same product
            engagement_name=f"E {scan_type} SameProd 2",  # Different engagement
            auto_create_context=True,
        )
        second_test = Test.objects.get(id=response_json["test"])

        # Product should have expected duplicates total
        prod_dup_count = Finding.objects.filter(test__engagement__product=first_test.engagement.product, duplicate=True).count()
        self.assertEqual(expected_duplicates, prod_dup_count)

        # Assess duplicate structure invariants on both tests
        self._assess_duplicates_in_test(first_test)
        self._assess_duplicates_in_test(second_test)

        return second_test.id

    def _test_same_product_different_engagements_dedupe_on_engagements_no_duplicates(self, filename, scan_type, expected_duplicates, first_import_duplicates=0):
        """
        Internal method to test importing into same product but different engagements with dedupe_on_engagements creates expected duplicates

        Args:
            expected_duplicates: Expected duplicates in second import (usually same as first for files with internal duplicates)
            first_import_duplicates: Expected duplicates in first import (for files with internal duplicates)

        """
        # First import: into Engagement A
        response_json = self.import_scan_with_params(
            filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=f"PT {scan_type} DedupeEng",
            product_name=f"P {scan_type} DedupeEng",
            engagement_name=f"E {scan_type} DedupeEng A",
            auto_create_context=True,
        )
        first_test = Test.objects.get(id=response_json["test"])

        # Set deduplication_on_engagement to True for the engagement
        first_test.engagement.deduplication_on_engagement = True
        first_test.engagement.save()

        # Second import: into Engagement B (same product, different engagement)
        response_json = self.import_scan_with_params(
            filename,
            scan_type=scan_type,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name=None,  # Use existing
            product_name=f"P {scan_type} DedupeEng",  # Same product
            engagement_name=f"E {scan_type} DedupeEng B",  # Different engagement
            auto_create_context=True,
        )
        second_test = Test.objects.get(id=response_json["test"])

        # The second test should contain expected duplicates because deduplication_on_engagement is True
        second_test_dup_count = Finding.objects.filter(test=second_test, duplicate=True).count()
        self.assertEqual(expected_duplicates, second_test_dup_count)

        # Product should have total duplicates from both imports
        total_expected_duplicates = first_import_duplicates + expected_duplicates
        prod_dup_count = Finding.objects.filter(test__engagement__product=first_test.engagement.product, duplicate=True).count()
        self.assertEqual(total_expected_duplicates, prod_dup_count)

        # Assess duplicate structure invariants on both tests
        self._assess_duplicates_in_test(first_test)
        self._assess_duplicates_in_test(second_test)

        return second_test.id

    # Duplicate structure assessment helpers
    def _assess_duplicates_in_test(self, test: Test):
        self._assert_duplicates_have_original(test)
        self._assert_duplicates_have_greater_id(test)
        self._assert_no_duplicate_loops(test)

    def _assert_duplicates_have_original(self, test: Test):
        for finding in Finding.objects.filter(test=test, duplicate=True):
            self.assertIsNotNone(
                finding.duplicate_finding,
                msg=f"Duplicate finding {finding.id} has no duplicate_finding set",
            )

    def _assert_duplicates_have_greater_id(self, test: Test):
        for finding in Finding.objects.filter(test=test, duplicate=True).select_related("duplicate_finding"):
            if finding.duplicate_finding is None:
                # Let the previous assertion report this
                continue
            self.assertTrue(
                finding.id > finding.duplicate_finding.id,
                msg=f"Duplicate finding {finding.id} should reference an original with a lower id ({finding.duplicate_finding.id})",
            )

    def _assert_no_duplicate_loops(self, test: Test):
        for finding in Finding.objects.filter(test=test, duplicate=True).select_related("duplicate_finding"):
            # A duplicate cannot point to another duplicate
            if finding.duplicate_finding is None:
                continue
            self.assertFalse(
                finding.duplicate_finding.duplicate,
                msg=f"Duplicate finding {finding.id} points to another duplicate {finding.duplicate_finding.id}",
            )

    # We need to cover all 4 types of deduplication algorithms:
    # - LEGACY (Zap)
    # - UNIQUE_ID_FROM_TOOL (Checkmarx)
    # - HASH_CODE (Trivy)
    # - UNIQUE_ID_FROM_TOOL_OR_HASH_CODE (SARIF)
    # - UNIQUE_ID_FROM_TOOL_OR_HASH_CODE (Veracode)
    # - UNIQUE_ID_FROM_TOOL_OR_HASH_CODE (StackHawk)

    # Test cases for ZAP (LEGACY algorithm)
    def test_zap_single_import_no_duplicates(self):
        """Test that importing ZAP scan (LEGACY algorithm) creates 0 duplicate findings"""
        self._test_single_import_assess_duplicates("scans/zap/dvwa_baseline_dojo.xml", "ZAP Scan", 0)

    def test_zap_full_then_subset_duplicates(self):
        """Test that importing full ZAP scan then subset creates duplicates"""
        self._test_full_then_subset_duplicates("scans/zap/dvwa_baseline_dojo.xml", "scans/zap/dvwa_baseline_dojo_subset.xml", "ZAP Scan", 10)

    def test_zap_different_products_no_duplicates(self):
        """Test that importing ZAP scan into different products creates 0 duplicates"""
        self._test_different_products_no_duplicates("scans/zap/dvwa_baseline_dojo.xml", "ZAP Scan", 0)

    def test_zap_same_product_different_engagements_duplicates(self):
        """Test that importing ZAP scan into same product but different engagements creates duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/zap/dvwa_baseline_dojo.xml", "ZAP Scan", 19)

    def test_zap_same_product_different_engagements_dedupe_on_engagements_no_duplicates(self):
        """Test that importing ZAP scan into same product but different engagements with dedupe_on_engagements creates 0 duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/zap/dvwa_baseline_dojo.xml", "ZAP Scan", 0)

    # Test cases for ZAP (LEGACY algorithm) with internal duplicates
    def test_zap_single_import_internal_duplicates(self):
        """Test that importing ZAP scan (LEGACY algorithm) creates 3 internal duplicates"""
        self._test_single_import_assess_duplicates("scans/zap/dvwa_baseline_dojo_fabricated_internal_duplicates.xml", "ZAP Scan", 3)

    def test_zap_full_then_subset_internal_duplicates(self):
        """Test that importing full ZAP scan then subset creates 3 internal duplicates + 6 cross engagement duplicates"""
        self._test_full_then_subset_duplicates("scans/zap/dvwa_baseline_dojo_fabricated_internal_duplicates.xml", "scans/zap/dvwa_baseline_dojo_fabricated_internal_duplicates_subset.xml", "ZAP Scan", 6, first_import_duplicates=3)

    def test_zap_different_products_internal_duplicates(self):
        """Test that importing ZAP scan into different products creates 3 internal duplicates"""
        self._test_different_products_no_duplicates("scans/zap/dvwa_baseline_dojo_fabricated_internal_duplicates.xml", "ZAP Scan", 3)

    def test_zap_same_product_different_engagements_internal_duplicates(self):
        """Test that importing ZAP scan into same product but different engagements creates 13 duplicates + 3 internal duplicates = 16 total duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/zap/dvwa_baseline_dojo_fabricated_internal_duplicates.xml", "ZAP Scan", 16)

    def test_zap_same_product_different_engagements_dedupe_on_engagements_internal_duplicates(self):
        """Test that importing ZAP scan with 3 internal dupcliates into same product but different engagements with dedupe_on_engagements creates only 3 duplicates and no cross engagement duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/zap/dvwa_baseline_dojo_fabricated_internal_duplicates.xml", "ZAP Scan", 3, first_import_duplicates=3)

    # Test cases for Checkmarx Scan detailed (UNIQUE_ID_FROM_TOOL algorithm)
    # Please note the non-detailed version uses HASH_CODE algorithm
    def test_checkmarx_single_import_no_duplicates(self):
        """Test that importing Checkmarx scan (UNIQUE_ID_FROM_TOOL algorithm) creates 0 duplicate findings"""
        self._test_single_import_assess_duplicates("scans/checkmarx/multiple_findings.json", "Checkmarx Scan detailed", 0)

    def test_checkmarx_full_then_subset_duplicates(self):
        """Test that importing full Checkmarx scan then subset creates duplicates"""
        # For now, use the same file for both full and subset
        self._test_full_then_subset_duplicates("scans/checkmarx/multiple_findings.json", "scans/checkmarx/multiple_findings_fabricated_subset.json",
        "Checkmarx Scan detailed", 5)

    def test_checkmarx_different_products_no_duplicates(self):
        """Test that importing Checkmarx scan into different products creates 0 duplicates"""
        self._test_different_products_no_duplicates("scans/checkmarx/multiple_findings.json", "Checkmarx Scan detailed", 0)

    def test_checkmarx_same_product_different_engagements_duplicates(self):
        """Test that importing Checkmarx scan into same product but different engagements creates duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/checkmarx/multiple_findings.json", "Checkmarx Scan detailed", 10)

    def test_checkmarx_same_product_different_engagements_dedupe_on_engagements_no_duplicates(self):
        """Test that importing Checkmarx scan into same product but different engagements with dedupe_on_engagements creates 0 duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/checkmarx/multiple_findings.json",
        "Checkmarx Scan detailed", 0)

    # Test cases for Checkmarx Scan detailed (UNIQUE_ID_FROM_TOOL algorithm) with internal duplicates
    # Please note the non-detailed version uses HASH_CODE algorithm
    def test_checkmarx_single_import_internal_duplicates(self):
        """Test that importing Checkmarx scan (UNIQUE_ID_FROM_TOOL algorithm) creates 5 internal duplicates"""
        self._test_single_import_assess_duplicates("scans/checkmarx/multiple_findings_fabricated_internal_duplicates.json", "Checkmarx Scan detailed", 6)

    def test_checkmarx_full_then_subset_internal_duplicates(self):
        """Test that importing full Checkmarx scan then subset creates 3 internal duplicates + 6 cross engagement duplicates"""
        self._test_full_then_subset_duplicates("scans/checkmarx/multiple_findings_fabricated_internal_duplicates.json", "scans/checkmarx/multiple_findings_fabricated_internal_duplicates_subset.json", "Checkmarx Scan detailed", 6, first_import_duplicates=6)

    def test_checkmarx_different_products_internal_duplicates(self):
        """Test that importing Checkmarx scan into different products creates 5 internal duplicates"""
        self._test_different_products_no_duplicates("scans/checkmarx/multiple_findings_fabricated_internal_duplicates.json", "Checkmarx Scan detailed", 6)

    def test_checkmarx_same_product_different_engagements_internal_duplicates(self):
        """Test that importing Checkmarx scan into same product but different engagements creates 13 duplicates + 3 internal duplicates = 16 total duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/checkmarx/multiple_findings_fabricated_internal_duplicates.json", "Checkmarx Scan detailed", 16)

    def test_checkmarx_same_product_different_engagements_dedupe_on_engagements_internal_duplicates(self):
        """Test that importing Checkmarx scan with 6 internal dupcliates into same product but different engagements with dedupe_on_engagements creates only 6 duplicates and no cross engagement duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/checkmarx/multiple_findings_fabricated_internal_duplicates.json", "Checkmarx Scan detailed", 6, first_import_duplicates=6)

    # Test cases for Trivy (HASH_CODE algorithm)
    def test_trivy_single_import_no_duplicates(self):
        """Test that importing Trivy scan (HASH_CODE algorithm) creates 0 duplicate findings"""
        self._test_single_import_assess_duplicates("scans/trivy/kubernetes.json", "Trivy Scan", 0)

    def test_trivy_full_then_subset_duplicates(self):
        """Test that importing full Trivy scan then subset creates duplicates"""
        # For now, use the same file for both full and subset
        self._test_full_then_subset_duplicates("scans/trivy/kubernetes.json", "scans/trivy/kubernetes_fabricated_subset.json", "Trivy Scan", 13)

    def test_trivy_different_products_no_duplicates(self):
        """Test that importing Trivy scan into different products creates 0 duplicates"""
        self._test_different_products_no_duplicates("scans/trivy/kubernetes.json", "Trivy Scan", 0)

    def test_trivy_same_product_different_engagements_duplicates(self):
        """Test that importing Trivy scan into same product but different engagements creates duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/trivy/kubernetes.json", "Trivy Scan", 20)

    def test_trivy_same_product_different_engagements_dedupe_on_engagements_no_duplicates(self):
        """Test that importing Trivy scan into same product but different engagements with dedupe_on_engagements creates 0 duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/trivy/kubernetes.json", "Trivy Scan", 0)

    # Test cases for Trivy (HASH_CODE algorithm) with internal duplicates
    def test_trivy_single_import_internal_duplicates(self):
        """Test that importing Trivy scan (HASH_CODE algorithm) creates 3 internal duplicates"""
        self._test_single_import_assess_duplicates("scans/trivy/kubernetes_fabricated_internal_duplicates.json", "Trivy Scan", 3)

    def test_trivy_full_then_subset_internal_duplicates(self):
        """Test that importing full Trivy scan then subset creates 3 internal duplicates + 5 cross engagement duplicates"""
        self._test_full_then_subset_duplicates("scans/trivy/kubernetes_fabricated_internal_duplicates.json", "scans/trivy/kubernetes_fabricated_internal_duplicates_subset.json", "Trivy Scan", 5, first_import_duplicates=3)

    def test_trivy_different_products_internal_duplicates(self):
        """Test that importing Trivy scan into different products creates 3 internal duplicates"""
        self._test_different_products_no_duplicates("scans/trivy/kubernetes_fabricated_internal_duplicates.json", "Trivy Scan", 3)

    def test_trivy_same_product_different_engagements_internal_duplicates(self):
        """Test that importing Trivy scan into same product but different engagements creates 13 duplicates + 3 internal duplicates = 16 total duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/trivy/kubernetes_fabricated_internal_duplicates.json", "Trivy Scan", 16)

    def test_trivy_same_product_different_engagements_dedupe_on_engagements_internal_duplicates(self):
        """Test that importing Trivy scan with 6 internal dupcliates into same product but different engagements with dedupe_on_engagements creates only 3 duplicates and no cross engagement duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/trivy/kubernetes_fabricated_internal_duplicates.json", "Trivy Scan", 3, first_import_duplicates=3)

    # Test cases for SARIF (UNIQUE_ID_FROM_TOOL_OR_HASH_CODE algorithm)
    # The samples for SARIF is the bash report that has internal duplicates
    # These are used on purpose so we capture the behaviour of import and reimport in this scenario.
    def test_sarif_single_import_no_duplicates(self):
        """Test that importing SARIF scan (UNIQUE_ID_FROM_TOOL_OR_HASH_CODE algorithm) creates 0 duplicate findings"""
        # bash-report.sarif has 18 internal duplicates, so we expect 18 duplicates even on first import
        test_id = self._test_single_import_assess_duplicates("scans/sarif/bash-report-fabricated-no-internal-dupes.sarif", "SARIF", 0)

        # duplicates should be sorted by id (currently not usefull as tests are running celery tasks in the foreground)
        for finding in Finding.objects.filter(test_id=test_id, duplicate=True):
            self.assertTrue(finding.duplicate_finding.id < finding.id)

    def test_sarif_full_then_subset_duplicates(self):
        """Test that importing full SARIF scan then subset creates duplicates"""
        # For now, use the same file for both full and subset
        # First import has 18 internal duplicates, second import also has 18 internal duplicates + 9 cross-import duplicates = 27 total in second test
        # Total = 18 (first) + 27 (second) = 45
        self._test_full_then_subset_duplicates("scans/sarif/bash-report-fabricated-no-internal-dupes.sarif", "scans/sarif/bash-report-fabricated-no-internal-dupes-subset.sarif", "SARIF", 4)

    def test_sarif_different_products_no_duplicates(self):
        """Test that importing SARIF scan into different products creates 0 duplicates"""
        # bash-report.sarif has 18 internal duplicates per import
        self._test_different_products_no_duplicates("scans/sarif/bash-report-fabricated-no-internal-dupes.sarif", "SARIF", 0)

    def test_sarif_same_product_different_engagements_duplicates(self):
        """Test that importing SARIF scan into same product but different engagements creates duplicates"""
        # 18 internal duplicates in first import + 18 in second import + 9 cross-import duplicates = 45 total
        self._test_same_product_different_engagements_duplicates("scans/sarif/bash-report-fabricated-no-internal-dupes.sarif", "SARIF", 5)

    def test_sarif_same_product_different_engagements_dedupe_on_engagements_no_duplicates(self):
        """Test that importing SARIF scan into same product but different engagements with dedupe_on_engagements creates 0 duplicates"""
        # bash-report.sarif has 18 internal duplicates per import
        # Second test has 18 internal duplicates (no cross-engagement duplicates due to dedupe_on_engagements=True)
        # Total product duplicates = 18 (first) + 18 (second) = 36
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/sarif/bash-report-fabricated-no-internal-dupes.sarif", "SARIF", 0)

    # Test cases for SARIF (UNIQUE_ID_FROM_TOOL_OR_HASH_CODE algorithm) with internal duplicates
    # The samples for SARIF is the bash report that has internal duplicates
    # These are used on purpose so we capture the behaviour of import and reimport in this scenario.
    def test_sarif_single_import_internal_duplicates(self):
        """Test that importing SARIF scan (UNIQUE_ID_FROM_TOOL_OR_HASH_CODE algorithm) creates 18 internal duplicates"""
        # bash-report.sarif has 18 internal duplicates, so we expect 18 duplicates even on first import
        test_id = self._test_single_import_assess_duplicates("scans/sarif/bash-report.sarif", "SARIF", 18)

        # duplicates should be sorted by id (currently not usefull as tests are running celery tasks in the foreground)
        for finding in Finding.objects.filter(test_id=test_id, duplicate=True):
            self.assertTrue(finding.duplicate_finding.id < finding.id)

    def test_sarif_full_then_subset_internal_duplicates(self):
        """Test that importing full SARIF scan then subset creates 18 internal duplicates + 9 cross-import duplicates = 27 duplicates in second import"""
        # For now, use the same file for both full and subset
        # First import has 18 internal duplicates, second import also has 18 internal duplicates + 9 cross-import duplicates = 27 total in second test
        # Total = 18 (first) + 27 (second) = 45
        self._test_full_then_subset_duplicates("scans/sarif/bash-report.sarif", "scans/sarif/bash-report.sarif", "SARIF", 27, first_import_duplicates=18)

    def test_sarif_different_products_internal_duplicates(self):
        """Test that importing SARIF scan into different products creates 18 internal duplicates per import"""
        # bash-report.sarif has 18 internal duplicates per import
        self._test_different_products_no_duplicates("scans/sarif/bash-report.sarif", "SARIF", 18)

    def test_sarif_same_product_different_engagements_internal_duplicates(self):
        """Test that importing SARIF scan into same product but different engagements creates 45 total duplicates (18 + 18 + 9)"""
        # 18 internal duplicates in first import + 18 in second import + 9 cross-import duplicates = 45 total
        self._test_same_product_different_engagements_duplicates("scans/sarif/bash-report.sarif", "SARIF", 45)

    def test_sarif_same_product_different_engagements_dedupe_on_engagements_internal_duplicates(self):
        """Test that importing SARIF scan with 18 internal duplicates into same product but different engagements with dedupe_on_engagements creates only 18 duplicates (no cross-engagement duplicates)"""
        # bash-report.sarif has 18 internal duplicates per import
        # Second test has 18 internal duplicates (no cross-engagement duplicates due to dedupe_on_engagements=True)
        # Total product duplicates = 18 (first) + 18 (second) = 36
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/sarif/bash-report.sarif", "SARIF",
        18, first_import_duplicates=18)

    # Test cases for Veracode (UNIQUE_ID_FROM_TOOL_OR_HASH_CODE algorithm)
    def test_veracode_single_import_no_duplicates(self):
        """Test that importing Veracode scan (UNIQUE_ID_FROM_TOOL_OR_HASH_CODE algorithm) creates 0 duplicate findings"""
        self._test_single_import_assess_duplicates("scans/veracode/veracode_scan.xml", "Veracode Scan", 0)

    def test_veracode_full_then_subset_duplicates(self):
        """Test that importing full Veracode scan then subset creates duplicates"""
        # For now, use the same file for both full and subset
        self._test_full_then_subset_duplicates("scans/veracode/veracode_scan.xml", "scans/veracode/veracode_scan.xml", "Veracode Scan", 7)

    def test_veracode_different_products_no_duplicates(self):
        """Test that importing Veracode scan into different products creates 0 duplicates"""
        self._test_different_products_no_duplicates("scans/veracode/veracode_scan.xml", "Veracode Scan", 0)

    def test_veracode_same_product_different_engagements_duplicates(self):
        """Test that importing Veracode scan into same product but different engagements creates duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/veracode/veracode_scan.xml", "Veracode Scan", 7)

    def test_veracode_same_product_different_engagements_dedupe_on_engagements_no_duplicates(self):
        """Test that importing Veracode scan into same product but different engagements with dedupe_on_engagements creates 0 duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/veracode/veracode_scan.xml", "Veracode Scan", 0)

    # Test cases for StackHawk (HASH_CODE algorithm)
    def test_stackhawk_single_import_no_duplicates(self):
        """Test that importing StackHawk scan (HASH_CODE algorithm) creates 0 duplicate findings"""
        self._test_single_import_assess_duplicates("scans/stackhawk/stackhawk_many_vul_without_duplicated_findings.json", "StackHawk HawkScan", 0)

    def test_stackhawk_full_then_subset_duplicates(self):
        """Test that importing full StackHawk scan then subset creates duplicates"""
        self._test_full_then_subset_duplicates("scans/stackhawk/stackhawk_many_vul_without_duplicated_findings.json",
        "scans/stackhawk/stackhawk_many_vul_without_duplicated_findings_subset.json", "StackHawk HawkScan", 5)

    def test_stackhawk_different_products_no_duplicates(self):
        """Test that importing StackHawk scan into different products creates 0 duplicates"""
        self._test_different_products_no_duplicates("scans/stackhawk/stackhawk_many_vul_without_duplicated_findings.json", "StackHawk HawkScan", 0)

    def test_stackhawk_same_product_different_engagements_duplicates(self):
        """Test that importing StackHawk scan into same product but different engagements creates duplicates"""
        self._test_same_product_different_engagements_duplicates("scans/stackhawk/stackhawk_many_vul_without_duplicated_findings.json",
        "StackHawk HawkScan", 6)

    def test_stackhawk_same_product_different_engagements_dedupe_on_engagements_no_duplicates(self):
        """Test that importing StackHawk scan into same product but different engagements with dedupe_on_engagements creates 0 duplicates"""
        self._test_same_product_different_engagements_dedupe_on_engagements_no_duplicates("scans/stackhawk/stackhawk_many_vul_without_duplicated_findings.json",
        "StackHawk HawkScan", 0)
