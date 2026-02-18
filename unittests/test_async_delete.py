"""
Unit tests for async_delete functionality.

These tests verify that the async_delete class works correctly with dojo_dispatch_task,
which injects user context and _pgh_context kwargs into task calls.

The original bug was that @app.task decorated instance methods didn't properly handle
the injected kwargs, causing TypeError for unexpected keyword arguments.
"""
import logging

from crum import impersonate
from django.contrib.auth.models import User
from django.test import override_settings
from django.utils import timezone

from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type, UserContactInfo
from dojo.utils import async_delete

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestAsyncDelete(DojoTestCase):

    """
    Test async_delete functionality with dojo_dispatch_task kwargs injection.

    These tests use block_execution=True and crum.impersonate to run tasks synchronously,
    which allows errors to surface immediately rather than being lost in background workers.
    """

    def setUp(self):
        """Set up test user with block_execution=True and disable unneeded features."""
        super().setUp()

        # Create test user with block_execution=True to run tasks synchronously
        self.testuser = User.objects.create(
            username="test_async_delete_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)

        # Log in as the test user (for API client)
        self.client.force_login(self.testuser)

        # Disable features that might interfere with deletion
        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_jira=False)

        # Create base test data
        self.product_type = Product_Type.objects.create(name="Test Product Type for Async Delete")
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]

    def tearDown(self):
        """Clean up any remaining test data."""
        # Clean up in reverse order of dependencies
        Finding.objects.filter(test__engagement__product__prod_type=self.product_type).delete()
        Test.objects.filter(engagement__product__prod_type=self.product_type).delete()
        Engagement.objects.filter(product__prod_type=self.product_type).delete()
        Product.objects.filter(prod_type=self.product_type).delete()
        self.product_type.delete()

        super().tearDown()

    def _create_product(self, name="Test Product"):
        """Helper to create a product for testing."""
        return Product.objects.create(
            name=name,
            description="Test product for async delete",
            prod_type=self.product_type,
        )

    def _create_engagement(self, product, name="Test Engagement"):
        """Helper to create an engagement for testing."""
        return Engagement.objects.create(
            name=name,
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_test(self, engagement, name="Test"):
        """Helper to create a test for testing."""
        return Test.objects.create(
            engagement=engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, test, title="Test Finding"):
        """Helper to create a finding for testing."""
        return Finding.objects.create(
            test=test,
            title=title,
            severity="High",
            description="Test finding for async delete",
            mitigation="Test mitigation",
            impact="Test impact",
            reporter=self.testuser,
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_simple_object(self):
        """
        Test that async_delete works for a simple object (Finding).

        Finding is not in the async_delete mapping, so it falls back to direct delete.
        This tests that the module-level task accepts **kwargs properly.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test = self._create_test(engagement)
        finding = self._create_finding(test)
        finding_pk = finding.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # This would raise TypeError before the fix when injected kwargs
            # were not handled properly by task functions
            async_del = async_delete()
            async_del.delete(finding)

        # Verify the finding was deleted
        self.assertFalse(
            Finding.objects.filter(pk=finding_pk).exists(),
            "Finding should be deleted",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_test_with_findings(self):
        """
        Test that async_delete cascades deletion for Test objects.

        Test is in the async_delete mapping and should cascade delete its findings.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test = self._create_test(engagement)
        finding1 = self._create_finding(test, "Finding 1")
        finding2 = self._create_finding(test, "Finding 2")

        test_pk = test.pk
        finding1_pk = finding1.pk
        finding2_pk = finding2.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # Delete the test (should cascade to findings)
            async_del = async_delete()
            async_del.delete(test)

        # Verify all objects were deleted
        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            "Test should be deleted",
        )
        self.assertFalse(
            Finding.objects.filter(pk=finding1_pk).exists(),
            "Finding 1 should be deleted via cascade",
        )
        self.assertFalse(
            Finding.objects.filter(pk=finding2_pk).exists(),
            "Finding 2 should be deleted via cascade",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_engagement_with_tests(self):
        """
        Test that async_delete cascades deletion for Engagement objects.

        Engagement is in the async_delete mapping and should cascade delete
        its tests and findings.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test1 = self._create_test(engagement, "Test 1")
        test2 = self._create_test(engagement, "Test 2")
        finding1 = self._create_finding(test1, "Finding in Test 1")
        finding2 = self._create_finding(test2, "Finding in Test 2")

        engagement_pk = engagement.pk
        test1_pk = test1.pk
        test2_pk = test2.pk
        finding1_pk = finding1.pk
        finding2_pk = finding2.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # Delete the engagement (should cascade to tests and findings)
            async_del = async_delete()
            async_del.delete(engagement)

        # Verify all objects were deleted
        self.assertFalse(
            Engagement.objects.filter(pk=engagement_pk).exists(),
            "Engagement should be deleted",
        )
        self.assertFalse(
            Test.objects.filter(pk__in=[test1_pk, test2_pk]).exists(),
            "Tests should be deleted via cascade",
        )
        self.assertFalse(
            Finding.objects.filter(pk__in=[finding1_pk, finding2_pk]).exists(),
            "Findings should be deleted via cascade",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_product_with_hierarchy(self):
        """
        Test that async_delete cascades deletion for Product objects.

        Product is in the async_delete mapping and should cascade delete
        its engagements, tests, and findings.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test = self._create_test(engagement)
        finding = self._create_finding(test)

        product_pk = product.pk
        engagement_pk = engagement.pk
        test_pk = test.pk
        finding_pk = finding.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # Delete the product (should cascade to everything)
            async_del = async_delete()
            async_del.delete(product)

        # Verify all objects were deleted
        self.assertFalse(
            Product.objects.filter(pk=product_pk).exists(),
            "Product should be deleted",
        )
        self.assertFalse(
            Engagement.objects.filter(pk=engagement_pk).exists(),
            "Engagement should be deleted via cascade",
        )
        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            "Test should be deleted via cascade",
        )
        self.assertFalse(
            Finding.objects.filter(pk=finding_pk).exists(),
            "Finding should be deleted via cascade",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_accepts_sync_kwarg(self):
        """
        Test that async_delete passes through the sync kwarg properly.

        The sync=True kwarg forces synchronous execution for the top-level task.
        However, nested task dispatches still need user context to run synchronously,
        so we use impersonate here as well.
        """
        product = self._create_product()
        product_pk = product.pk

        # Use impersonate to ensure nested tasks also run synchronously
        with impersonate(self.testuser):
            # Explicitly pass sync=True
            async_del = async_delete()
            async_del.delete(product, sync=True)

        # Verify the product was deleted
        self.assertFalse(
            Product.objects.filter(pk=product_pk).exists(),
            "Product should be deleted with sync=True",
        )

    def test_async_delete_helper_methods(self):
        """
        Test that static helper methods on async_delete class still work.

        These are kept for backwards compatibility.
        """
        product = self._create_product()

        # Test get_object_name
        self.assertEqual(
            async_delete.get_object_name(product),
            "Product",
            "get_object_name should return class name",
        )

        # Test get_object_name with model class
        self.assertEqual(
            async_delete.get_object_name(Product),
            "Product",
            "get_object_name should work with model class",
        )

    def test_async_delete_mapping_preserved(self):
        """
        Test that the mapping attribute is preserved on async_delete instances.

        This ensures backwards compatibility for code that might access the mapping.
        """
        async_del = async_delete()

        # Verify mapping exists and has expected keys
        self.assertIsNotNone(async_del.mapping)
        self.assertIn("Product", async_del.mapping)
        self.assertIn("Product_Type", async_del.mapping)
        self.assertIn("Engagement", async_del.mapping)
        self.assertIn("Test", async_del.mapping)
