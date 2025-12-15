"""
Unit tests for audit configuration functionality.

Tests pghistory audit system configuration and event creation.
"""
import os
from unittest.mock import patch

from django.apps import apps
from django.conf import settings
from django.test import TestCase, override_settings

from dojo.auditlog import (
    configure_audit_system,
    configure_pghistory_triggers,
)
from dojo.models import Product_Type


class TestAuditConfig(TestCase):

    """Test audit configuration functionality."""

    @patch("dojo.auditlog.call_command")
    def test_configure_pghistory_triggers_enabled(self, mock_call_command):
        """Test that configure_pghistory_triggers enables triggers when audit logging is enabled."""
        with override_settings(ENABLE_AUDITLOG=True):
            configure_pghistory_triggers()

        # Verify that pgtrigger enable command was called
        mock_call_command.assert_called_with("pgtrigger", "enable")

    @patch("dojo.auditlog.call_command")
    def test_configure_pghistory_triggers_disabled(self, mock_call_command):
        """Test that configure_pghistory_triggers disables triggers when audit logging is disabled."""
        with override_settings(ENABLE_AUDITLOG=False):
            configure_pghistory_triggers()

        # Verify that pgtrigger disable command was called
        mock_call_command.assert_called_with("pgtrigger", "disable")

    @override_settings(ENABLE_AUDITLOG=True)
    def test_configure_audit_system_enabled(self):
        """Test that configure_audit_system configures pghistory when audit logging is enabled."""
        # Should not raise an exception
        configure_audit_system()

    @override_settings(ENABLE_AUDITLOG=False)
    def test_configure_audit_system_disabled(self):
        """Test that configure_audit_system handles disabled audit logging."""
        # Should not raise an exception
        configure_audit_system()

    @override_settings(ENABLE_AUDITLOG=True)
    def test_pghistory_insert_event_creation(self):
        """Test that pghistory creates insert events when a Product_Type is created."""
        # Configure audit system for pghistory
        configure_audit_system()
        configure_pghistory_triggers()

        # Get the Product_Type event model
        ProductTypeEvent = apps.get_model("dojo", "Product_TypeEvent")

        # Count existing events before creating new Product_Type
        initial_event_count = ProductTypeEvent.objects.count()

        # Create a new Product_Type
        product_type = Product_Type.objects.create(
            name="Test Product Type for pghistory",
            description="Test product type to verify pghistory event creation",
        )

        # Verify that an insert event was created in pghistory
        final_event_count = ProductTypeEvent.objects.count()
        self.assertEqual(final_event_count, initial_event_count + 1,
                        "Expected exactly one new pghistory event after creating Product_Type")

        # Get the most recent event
        latest_event = ProductTypeEvent.objects.latest("pgh_created_at")

        # Verify the event details
        self.assertEqual(latest_event.pgh_obj_id, product_type.id,
                        "Event should reference the created Product_Type")
        self.assertEqual(latest_event.name, product_type.name,
                        "Event should contain the Product_Type name")
        self.assertEqual(latest_event.description, product_type.description,
                        "Event should contain the Product_Type description")

        # Verify it's an insert event (check if pgh_label indicates creation)
        self.assertIsNotNone(latest_event.pgh_created_at,
                           "Event should have a creation timestamp")

        # Clean up
        product_type.delete()

    def test_configure_audit_system_fails_with_dd_auditlog_type_env(self):
        """Test that configure_audit_system fails if DD_AUDITLOG_TYPE environment variable is set."""
        # Temporarily set the environment variable
        original_value = os.environ.get("DD_AUDITLOG_TYPE")
        try:
            os.environ["DD_AUDITLOG_TYPE"] = "django-pghistory"
            with self.assertRaises(ValueError) as context:
                configure_audit_system()
            self.assertIn("DD_AUDITLOG_TYPE", str(context.exception))
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("DD_AUDITLOG_TYPE", None)
            else:
                os.environ["DD_AUDITLOG_TYPE"] = original_value

    def test_configure_audit_system_fails_with_auditlog_type_setting(self):
        """Test that configure_audit_system fails if AUDITLOG_TYPE setting is manually set."""
        # Temporarily add the setting
        original_value = getattr(settings, "AUDITLOG_TYPE", None)
        try:
            settings.AUDITLOG_TYPE = "django-pghistory"
            with self.assertRaises(ValueError) as context:
                configure_audit_system()
            self.assertIn("AUDITLOG_TYPE", str(context.exception))
        finally:
            # Restore original value
            if original_value is None:
                if hasattr(settings, "AUDITLOG_TYPE"):
                    delattr(settings, "AUDITLOG_TYPE")
            else:
                settings.AUDITLOG_TYPE = original_value
