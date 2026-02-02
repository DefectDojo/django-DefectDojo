"""
Unit tests for flush_auditlog functionality.

Tests the flush_auditlog management command and task that removes old audit log entries.
"""
import logging
from datetime import UTC, datetime

from dateutil.relativedelta import relativedelta
from django.apps import apps
from django.test import override_settings

from dojo.models import Product_Type
from dojo.tasks import flush_auditlog
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

logger = logging.getLogger(__name__)


@versioned_fixtures
class TestFlushAuditlog(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    @override_settings(AUDITLOG_FLUSH_RETENTION_PERIOD=-1)
    def test_flush_auditlog_disabled(self):
        """Test that flush_auditlog does nothing when retention period is -1 (disabled)."""
        # Get pghistory event model
        ProductTypeEvent = apps.get_model("dojo", "Product_TypeEvent")
        entries_before = ProductTypeEvent.objects.count()

        flush_auditlog()

        entries_after = ProductTypeEvent.objects.count()
        self.assertEqual(entries_before, entries_after)

    @override_settings(AUDITLOG_FLUSH_RETENTION_PERIOD=0)
    def test_delete_all_entries(self):
        """Test that flush_auditlog deletes all entries when retention period is 0."""
        # Get pghistory event model
        ProductTypeEvent = apps.get_model("dojo", "Product_TypeEvent")

        # Create a test product type to generate events
        product_type = Product_Type.objects.create(
            name="Test Product Type for Flush",
            description="Test description",
        )

        # Flush with retention period 0 (delete all)
        flush_auditlog()

        # All entries should be deleted
        entries_after = ProductTypeEvent.objects.count()
        self.assertEqual(entries_after, 0, "All entries should be deleted when retention period is 0")

        # Clean up
        product_type.delete()

    @override_settings(AUDITLOG_FLUSH_RETENTION_PERIOD=1)
    def test_delete_entries_with_retention_period(self):
        """Test that flush_auditlog deletes entries older than retention period."""
        # Get pghistory event model
        ProductTypeEvent = apps.get_model("dojo", "Product_TypeEvent")

        # Create a test product type
        product_type = Product_Type.objects.create(
            name="Test Product Type for Retention",
            description="Test description",
        )

        # Get the event created by the creation
        recent_event = ProductTypeEvent.objects.filter(pgh_obj_id=product_type.id).first()

        # Manually create an old event by updating the timestamp
        # Set it to 2 months ago so it will be deleted with retention period of 1 month
        if recent_event:
            two_months_ago = datetime.now(UTC) - relativedelta(months=2)
            # Update the created_at timestamp to make it old
            ProductTypeEvent.objects.filter(pk=recent_event.pk).update(pgh_created_at=two_months_ago)

        # Count events before flush
        entries_before = ProductTypeEvent.objects.count()

        # Flush with retention period of 1 month
        flush_auditlog()

        # Count events after flush
        entries_after = ProductTypeEvent.objects.count()

        # The old event should be deleted (2 months old > 1 month retention)
        self.assertLess(entries_after, entries_before, "Old entries should be deleted")

        # Clean up
        product_type.delete()
