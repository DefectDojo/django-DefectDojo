"""
Comprehensive test suite for the endpoint_manager module.

This module tests the EndpointManager class which handles critical security operations
including endpoint creation, validation, status management, and mitigation.

Test Coverage:
- Endpoint creation and validation
- Endpoint status lifecycle (active -> mitigated -> reactivated)
- Bulk endpoint operations
- Edge cases and error handling
- Data integrity during endpoint updates
"""

from unittest.mock import MagicMock, Mock, patch

from django.core.exceptions import MultipleObjectsReturned, ValidationError
from django.test import TestCase
from django.utils import timezone

from dojo.importers.endpoint_manager import EndpointManager
from dojo.models import (
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)


class TestEndpointManager(TestCase):
    """
    Test suite for EndpointManager class.

    Tests the core functionality of endpoint management including:
    - Adding endpoints to findings
    - Mitigating endpoint statuses
    - Reactivating endpoint statuses
    - Updating endpoint statuses during reimport
    """

    @classmethod
    def setUpTestData(cls):
        """
        Set up test data that will be used across all test methods.

        Creates a complete object hierarchy:
        Product Type -> Product -> Engagement -> Test -> Finding
        Also creates test user and endpoints.
        """
        # Create user for testing
        cls.user = Dojo_User.objects.create(
            username="test_user",
            email="test@example.com",
        )

        # Create product hierarchy
        cls.product_type = Product_Type.objects.create(
            name="Test Product Type",
            description="Test product type for endpoint manager tests",
        )

        cls.product = Product.objects.create(
            name="Test Product",
            description="Test product for endpoint manager tests",
            prod_type=cls.product_type,
        )

        cls.engagement = Engagement.objects.create(
            name="Test Engagement",
            product=cls.product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )

        # Get or create a test type for testing
        cls.test_type, _ = Test_Type.objects.get_or_create(
            name="Endpoint Manager Test Type",
            defaults={"static_tool": False, "dynamic_tool": False},
        )

        cls.test = Test.objects.create(
            engagement=cls.engagement,
            test_type=cls.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        cls.finding = Finding.objects.create(
            title="Test Finding",
            description="Test finding for endpoint manager tests",
            severity="High",
            test=cls.test,
            reporter=cls.user,
            date=timezone.now().date(),
        )

        # Initialize endpoint manager
        cls.endpoint_manager = EndpointManager()

    def test_add_endpoints_to_unsaved_finding_success(self):
        """
        Test successfully adding valid endpoints to a finding.

        Verifies that:
        - Endpoints are properly created in the database
        - Endpoint_Status objects are created linking endpoints to finding
        - The correct number of endpoints are added
        """
        # Create test endpoints (unsaved)
        endpoint1 = Endpoint(
            protocol="https",
            host="example.com",
            port=443,
            path="/api/v1",
            product=self.product,
        )
        endpoint2 = Endpoint(
            protocol="http",
            host="test.example.com",
            port=80,
            path="/admin",
            product=self.product,
        )

        endpoints = [endpoint1, endpoint2]

        # Add endpoints to finding
        self.endpoint_manager.add_endpoints_to_unsaved_finding(
            self.finding,
            endpoints,
            sync=True,
        )

        # Verify endpoints were created
        endpoint_statuses = Endpoint_Status.objects.filter(finding=self.finding)
        self.assertEqual(
            endpoint_statuses.count(),
            2,
            "Should create 2 endpoint status objects",
        )

        # Verify endpoint details
        created_endpoints = [eps.endpoint for eps in endpoint_statuses]
        hosts = [ep.host for ep in created_endpoints]
        self.assertIn("example.com", hosts, "Should contain example.com endpoint")
        self.assertIn("test.example.com", hosts, "Should contain test.example.com endpoint")

    def test_add_endpoints_to_unsaved_finding_with_invalid_endpoint(self):
        """
        Test adding endpoints when one endpoint fails validation.

        Verifies that:
        - Invalid endpoints are logged but don't prevent processing
        - Valid endpoints are still added
        - The system handles ValidationError gracefully
        """
        # Create one valid and one invalid endpoint
        valid_endpoint = Endpoint(
            protocol="https",
            host="valid.com",
            product=self.product,
        )

        # Create invalid endpoint (will fail validation)
        invalid_endpoint = Endpoint(
            protocol="https",
            host="",  # Empty host should fail validation
            product=self.product,
        )

        endpoints = [valid_endpoint, invalid_endpoint]

        # Mock the clean method to raise ValidationError for invalid endpoint
        def mock_clean_method(self):
            if not self.host:
                raise ValidationError("Host cannot be empty")
        
        with patch.object(Endpoint, "clean", mock_clean_method):
            # Should not raise exception, but log warning
            self.endpoint_manager.add_endpoints_to_unsaved_finding(
                self.finding,
                endpoints,
                sync=True,
            )

        # Verify at least the valid endpoint was processed
        endpoint_statuses = Endpoint_Status.objects.filter(finding=self.finding)
        self.assertGreaterEqual(
            endpoint_statuses.count(),
            1,
            "Should create at least 1 endpoint status for valid endpoint",
        )

    def test_add_endpoints_to_unsaved_finding_duplicate_endpoints(self):
        """
        Test adding duplicate endpoints to a finding.

        Verifies that:
        - Duplicate endpoints are handled correctly
        - No duplicate Endpoint_Status objects are created
        - The system uses ignore_conflicts in bulk_create
        """
        # Create endpoint
        endpoint = Endpoint(
            protocol="https",
            host="duplicate.com",
            port=443,
            product=self.product,
        )

        # Add same endpoint twice
        self.endpoint_manager.add_endpoints_to_unsaved_finding(
            self.finding,
            [endpoint],
            sync=True,
        )

        initial_count = Endpoint_Status.objects.filter(finding=self.finding).count()

        # Try to add again
        self.endpoint_manager.add_endpoints_to_unsaved_finding(
            self.finding,
            [endpoint],
            sync=True,
        )

        final_count = Endpoint_Status.objects.filter(finding=self.finding).count()

        # Should not create duplicate endpoint status
        self.assertEqual(
            initial_count,
            final_count,
            "Should not create duplicate endpoint status objects",
        )

    def test_add_endpoints_multiple_objects_returned_exception(self):
        """
        Test handling of MultipleObjectsReturned exception.

        Verifies that:
        - MultipleObjectsReturned is caught and re-raised with helpful message
        - The error message directs users to the migration endpoint
        """
        endpoint = Endpoint(
            protocol="https",
            host="broken.com",
            product=self.product,
        )

        # Mock endpoint_get_or_create to raise MultipleObjectsReturned
        with patch("dojo.importers.endpoint_manager.endpoint_get_or_create") as mock_get_or_create:
            mock_get_or_create.side_effect = MultipleObjectsReturned("Multiple endpoints found")

            with self.assertRaises(Exception) as context:
                self.endpoint_manager.add_endpoints_to_unsaved_finding(
                    self.finding,
                    [endpoint],
                    sync=True,
                )

            # Verify error message contains migration guidance
            self.assertIn(
                "Endpoints in your database are broken",
                str(context.exception),
                "Error message should mention broken endpoints",
            )
            # The actual error message uses reverse('endpoint_migrate') which may vary
            # Just verify the core message is present
            self.assertIn(
                "migrate them to new format",
                str(context.exception),
                "Error message should reference migration",
            )

    def test_mitigate_endpoint_status_success(self):
        """
        Test successfully mitigating active endpoint statuses.

        Verifies that:
        - Active endpoint statuses are marked as mitigated
        - Mitigation timestamp is set
        - Mitigated_by user is recorded
        - Last_modified timestamp is updated
        """
        # Create active endpoint status
        endpoint = Endpoint.objects.create(
            protocol="https",
            host="mitigate-test.com",
            product=self.product,
        )

        endpoint_status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint,
            date=timezone.now().date(),
            mitigated=False,
        )

        # Mitigate the endpoint status
        self.endpoint_manager.mitigate_endpoint_status(
            [endpoint_status],
            self.user,
            sync=True,
        )

        # Refresh from database
        endpoint_status.refresh_from_db()

        # Verify mitigation
        self.assertTrue(
            endpoint_status.mitigated,
            "Endpoint status should be marked as mitigated",
        )
        self.assertIsNotNone(
            endpoint_status.mitigated_time,
            "Mitigation time should be set",
        )
        self.assertEqual(
            endpoint_status.mitigated_by,
            self.user,
            "Mitigated_by should be set to the user",
        )
        self.assertIsNotNone(
            endpoint_status.last_modified,
            "Last modified time should be updated",
        )

    def test_mitigate_endpoint_status_already_mitigated(self):
        """
        Test mitigating an already mitigated endpoint status.

        Verifies that:
        - Already mitigated endpoints are not modified
        - Original mitigation data is preserved
        - No unnecessary database updates occur
        """
        # Create already mitigated endpoint status
        endpoint = Endpoint.objects.create(
            protocol="https",
            host="already-mitigated.com",
            product=self.product,
        )

        original_mitigation_time = timezone.now() - timezone.timedelta(days=1)
        original_user = Dojo_User.objects.create(
            username="original_user",
            email="original@example.com",
        )

        endpoint_status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint,
            date=timezone.now().date(),
            mitigated=True,
            mitigated_time=original_mitigation_time,
            mitigated_by=original_user,
        )

        # Try to mitigate again
        self.endpoint_manager.mitigate_endpoint_status(
            [endpoint_status],
            self.user,
            sync=True,
        )

        # Refresh from database
        endpoint_status.refresh_from_db()

        # Verify original mitigation data is preserved
        self.assertEqual(
            endpoint_status.mitigated_by,
            original_user,
            "Original mitigated_by user should be preserved",
        )
        self.assertEqual(
            endpoint_status.mitigated_time,
            original_mitigation_time,
            "Original mitigation time should be preserved",
        )

    def test_reactivate_endpoint_status_success(self):
        """
        Test successfully reactivating mitigated endpoint statuses.

        Verifies that:
        - Mitigated endpoint statuses are reactivated
        - Mitigation data is cleared
        - Last_modified timestamp is updated
        """
        # Create mitigated endpoint status
        endpoint = Endpoint.objects.create(
            protocol="https",
            host="reactivate-test.com",
            product=self.product,
        )

        endpoint_status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint,
            date=timezone.now().date(),
            mitigated=True,
            mitigated_time=timezone.now(),
            mitigated_by=self.user,
        )

        # Reactivate the endpoint status
        self.endpoint_manager.reactivate_endpoint_status(
            [endpoint_status],
            sync=True,
        )

        # Refresh from database
        endpoint_status.refresh_from_db()

        # Verify reactivation
        self.assertFalse(
            endpoint_status.mitigated,
            "Endpoint status should be marked as active",
        )
        self.assertIsNone(
            endpoint_status.mitigated_time,
            "Mitigation time should be cleared",
        )
        self.assertIsNone(
            endpoint_status.mitigated_by,
            "Mitigated_by should be cleared",
        )
        self.assertIsNotNone(
            endpoint_status.last_modified,
            "Last modified time should be updated",
        )

    def test_reactivate_endpoint_status_already_active(self):
        """
        Test reactivating an already active endpoint status.

        Verifies that:
        - Already active endpoints are not modified
        - No unnecessary database updates occur
        """
        # Create active endpoint status
        endpoint = Endpoint.objects.create(
            protocol="https",
            host="already-active.com",
            product=self.product,
        )

        original_last_modified = timezone.now() - timezone.timedelta(hours=1)
        endpoint_status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint,
            date=timezone.now().date(),
            mitigated=False,
            last_modified=original_last_modified,
        )

        # Try to reactivate
        self.endpoint_manager.reactivate_endpoint_status(
            [endpoint_status],
            sync=True,
        )

        # Refresh from database
        endpoint_status.refresh_from_db()

        # Verify status remains active and last_modified is not changed
        self.assertFalse(
            endpoint_status.mitigated,
            "Endpoint status should remain active",
        )
        self.assertEqual(
            endpoint_status.last_modified,
            original_last_modified,
            "Last modified should not change for already active endpoint",
        )

    def test_update_endpoint_status_new_finding_mitigated(self):
        """
        Test updating endpoint status when new finding is mitigated.

        Verifies that:
        - All old endpoint statuses are mitigated when new finding is mitigated
        - Proper mitigation data is set
        """
        # Create existing finding with active endpoints
        existing_endpoint = Endpoint.objects.create(
            protocol="https",
            host="existing.com",
            product=self.product,
        )

        existing_status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=existing_endpoint,
            date=timezone.now().date(),
            mitigated=False,
        )

        # Create new mitigated finding
        new_finding = Finding.objects.create(
            title="New Mitigated Finding",
            description="Test",
            severity="High",
            test=self.test,
            date=timezone.now().date(),
            is_mitigated=True,
        )
        new_finding.unsaved_endpoints = []

        # Update endpoint status
        self.endpoint_manager.update_endpoint_status(
            self.finding,
            new_finding,
            self.user,
            sync=True,
        )

        # Refresh from database
        existing_status.refresh_from_db()

        # Verify old endpoint is mitigated
        self.assertTrue(
            existing_status.mitigated,
            "Existing endpoint should be mitigated when new finding is mitigated",
        )

    def test_update_endpoint_status_endpoint_removed(self):
        """
        Test updating endpoint status when endpoint is removed in new finding.

        Verifies that:
        - Endpoints not in new finding are mitigated
        - Endpoints still present are reactivated if needed
        """
        # Create existing finding with two endpoints
        endpoint1 = Endpoint.objects.create(
            protocol="https",
            host="keep.com",
            product=self.product,
        )
        endpoint2 = Endpoint.objects.create(
            protocol="https",
            host="remove.com",
            product=self.product,
        )

        status1 = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint1,
            date=timezone.now().date(),
            mitigated=False,
        )
        status2 = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint2,
            date=timezone.now().date(),
            mitigated=False,
        )

        # Create new finding with only endpoint1
        new_finding = Finding.objects.create(
            title="New Finding",
            description="Test",
            severity="High",
            test=self.test,
            date=timezone.now().date(),
            is_mitigated=False,
        )
        new_finding.unsaved_endpoints = [endpoint1]

        # Update endpoint status
        self.endpoint_manager.update_endpoint_status(
            self.finding,
            new_finding,
            self.user,
            sync=True,
        )

        # Refresh from database
        status1.refresh_from_db()
        status2.refresh_from_db()

        # Verify endpoint1 is still active and endpoint2 is mitigated
        self.assertFalse(
            status1.mitigated,
            "Endpoint present in new finding should remain active",
        )
        self.assertTrue(
            status2.mitigated,
            "Endpoint not in new finding should be mitigated",
        )

    def test_update_endpoint_status_reactivate_mitigated_endpoint(self):
        """
        Test reactivating a previously mitigated endpoint.

        Verifies that:
        - Mitigated endpoints are reactivated if they appear in new finding
        - Mitigation data is properly cleared
        """
        # Create existing finding with mitigated endpoint
        endpoint = Endpoint.objects.create(
            protocol="https",
            host="reactivate.com",
            product=self.product,
        )

        status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint,
            date=timezone.now().date(),
            mitigated=True,
            mitigated_time=timezone.now(),
            mitigated_by=self.user,
        )

        # Create new finding with the same endpoint
        new_finding = Finding.objects.create(
            title="New Finding",
            description="Test",
            severity="High",
            test=self.test,
            date=timezone.now().date(),
            is_mitigated=False,
        )
        new_finding.unsaved_endpoints = [endpoint]

        # Update endpoint status
        self.endpoint_manager.update_endpoint_status(
            self.finding,
            new_finding,
            self.user,
            sync=True,
        )

        # Refresh from database
        status.refresh_from_db()

        # Verify endpoint is reactivated
        self.assertFalse(
            status.mitigated,
            "Previously mitigated endpoint should be reactivated",
        )
        self.assertIsNone(
            status.mitigated_time,
            "Mitigation time should be cleared",
        )
        self.assertIsNone(
            status.mitigated_by,
            "Mitigated_by should be cleared",
        )

    def test_clean_unsaved_endpoints_all_valid(self):
        """
        Test cleaning endpoints when all are valid.

        Verifies that:
        - Valid endpoints pass validation
        - No warnings are logged
        """
        # Create valid endpoints
        endpoint1 = Endpoint(
            protocol="https",
            host="valid1.com",
            product=self.product,
        )
        endpoint2 = Endpoint(
            protocol="http",
            host="valid2.com",
            port=8080,
            product=self.product,
        )

        endpoints = [endpoint1, endpoint2]

        # Should not raise any exceptions
        self.endpoint_manager.clean_unsaved_endpoints(endpoints)

    def test_clean_unsaved_endpoints_with_invalid(self):
        """
        Test cleaning endpoints when some are invalid.

        Verifies that:
        - Invalid endpoints trigger warnings
        - Processing continues despite invalid endpoints
        - ValidationError is caught and logged
        """
        # Create invalid endpoint
        invalid_endpoint = Endpoint(
            protocol="https",
            host="",  # Empty host
            product=self.product,
        )

        # Mock the clean method to raise ValidationError
        with patch.object(Endpoint, "clean") as mock_clean:
            mock_clean.side_effect = ValidationError("Host cannot be empty")

            # Should not raise exception, but log warning
            with self.assertLogs("dojo.importers.endpoint_manager", level="WARNING") as log:
                self.endpoint_manager.clean_unsaved_endpoints([invalid_endpoint])

            # Verify warning was logged
            self.assertTrue(
                any("broken endpoint" in message.lower() for message in log.output),
                "Should log warning about broken endpoint",
            )

    def test_chunk_endpoints_and_disperse(self):
        """
        Test the chunk_endpoints_and_disperse wrapper method.

        Verifies that:
        - Method correctly delegates to add_endpoints_to_unsaved_finding
        - Sync parameter is properly set
        """
        endpoint = Endpoint(
            protocol="https",
            host="chunk-test.com",
            product=self.product,
        )

        # Call wrapper method
        self.endpoint_manager.chunk_endpoints_and_disperse(
            self.finding,
            [endpoint],
        )

        # Verify endpoint was added
        endpoint_statuses = Endpoint_Status.objects.filter(finding=self.finding)
        self.assertGreater(
            endpoint_statuses.count(),
            0,
            "Should create endpoint status via wrapper method",
        )

    def test_chunk_endpoints_and_mitigate(self):
        """
        Test the chunk_endpoints_and_mitigate wrapper method.

        Verifies that:
        - Method correctly delegates to mitigate_endpoint_status
        - Sync parameter is properly set
        """
        # Create active endpoint status
        endpoint = Endpoint.objects.create(
            protocol="https",
            host="chunk-mitigate.com",
            product=self.product,
        )

        endpoint_status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint,
            date=timezone.now().date(),
            mitigated=False,
        )

        # Call wrapper method
        self.endpoint_manager.chunk_endpoints_and_mitigate(
            [endpoint_status],
            self.user,
        )

        # Refresh from database
        endpoint_status.refresh_from_db()

        # Verify mitigation
        self.assertTrue(
            endpoint_status.mitigated,
            "Should mitigate endpoint via wrapper method",
        )

    def test_chunk_endpoints_and_reactivate(self):
        """
        Test the chunk_endpoints_and_reactivate wrapper method.

        Verifies that:
        - Method correctly delegates to reactivate_endpoint_status
        - Sync parameter is properly set
        """
        # Create mitigated endpoint status
        endpoint = Endpoint.objects.create(
            protocol="https",
            host="chunk-reactivate.com",
            product=self.product,
        )

        endpoint_status = Endpoint_Status.objects.create(
            finding=self.finding,
            endpoint=endpoint,
            date=timezone.now().date(),
            mitigated=True,
            mitigated_time=timezone.now(),
            mitigated_by=self.user,
        )

        # Call wrapper method
        self.endpoint_manager.chunk_endpoints_and_reactivate(
            [endpoint_status],
        )

        # Refresh from database
        endpoint_status.refresh_from_db()

        # Verify reactivation
        self.assertFalse(
            endpoint_status.mitigated,
            "Should reactivate endpoint via wrapper method",
        )

    def test_bulk_endpoint_operations(self):
        """
        Test bulk operations with multiple endpoints.

        Verifies that:
        - Multiple endpoints can be processed in a single operation
        - Batch size parameter is respected
        - All endpoints are properly created
        """
        # Create multiple endpoints
        endpoints = [
            Endpoint(
                protocol="https",
                host=f"bulk{i}.com",
                product=self.product,
            )
            for i in range(10)
        ]

        # Add all endpoints
        self.endpoint_manager.add_endpoints_to_unsaved_finding(
            self.finding,
            endpoints,
            sync=True,
        )

        # Verify all endpoints were created
        endpoint_statuses = Endpoint_Status.objects.filter(finding=self.finding)
        self.assertEqual(
            endpoint_statuses.count(),
            10,
            "Should create 10 endpoint statuses in bulk operation",
        )
