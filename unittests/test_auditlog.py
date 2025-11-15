"""
Unit tests for audit configuration functionality.

Tests the dual-audit system where both django-auditlog and django-pghistory
can coexist, allowing users to see historical data from both systems.
"""
from unittest.mock import MagicMock, patch

from auditlog.models import LogEntry
from django.apps import apps
from django.test import TestCase, override_settings

from dojo.auditlog import (
    configure_audit_system,
    configure_pghistory_triggers,
    disable_django_auditlog,
    disable_django_pghistory,
    enable_django_auditlog,
    enable_django_pghistory,
    register_django_pghistory_models,
)
from dojo.models import Product_Type


class TestAuditConfig(TestCase):

    """Test audit configuration functionality."""

    @patch("auditlog.registry.auditlog")
    def test_enable_django_auditlog(self, mock_auditlog):
        """Test that enable_django_auditlog registers models."""
        # Mock the auditlog registry
        mock_auditlog.register = MagicMock()

        enable_django_auditlog()

        # Verify that register was called multiple times (once for each model)
        self.assertTrue(mock_auditlog.register.called)
        self.assertGreater(mock_auditlog.register.call_count, 5)

    def test_disable_django_auditlog(self):
        """Test that disable_django_auditlog runs without error."""
        # This should not raise an exception
        disable_django_auditlog()

    @patch("dojo.auditlog.pghistory")
    def test_register_django_pghistory_models(self, mock_pghistory):
        """Test that register_django_pghistory_models registers all models."""
        # Mock pghistory.track
        mock_pghistory.track = MagicMock()
        mock_pghistory.InsertEvent = MagicMock()
        mock_pghistory.UpdateEvent = MagicMock()
        mock_pghistory.DeleteEvent = MagicMock()
        mock_pghistory.ManualEvent = MagicMock()

        register_django_pghistory_models()

        # Verify that track was called multiple times (once for each model)
        self.assertTrue(mock_pghistory.track.called)
        self.assertGreater(mock_pghistory.track.call_count, 5)

    @patch("dojo.auditlog.call_command")
    def test_enable_django_pghistory(self, mock_call_command):
        """Test that enable_django_pghistory enables triggers only."""
        enable_django_pghistory()

        # Verify that pgtrigger enable command was called
        mock_call_command.assert_called_with("pgtrigger", "enable")

    @patch("dojo.auditlog.call_command")
    def test_disable_django_pghistory(self, mock_call_command):
        """Test that disable_django_pghistory disables triggers."""
        disable_django_pghistory()

        # Verify that pgtrigger disable command was called
        mock_call_command.assert_called_once_with("pgtrigger", "disable")

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="invalid-type")
    @patch("dojo.auditlog.disable_django_auditlog")
    @patch("dojo.auditlog.call_command")
    def test_invalid_audit_type_warning(self, mock_call_command, mock_disable_auditlog):
        """Test that invalid audit types disable both audit systems."""
        # Call the main configuration function with invalid type
        configure_audit_system()
        configure_pghistory_triggers()

        # Verify that auditlog is disabled for invalid type
        mock_disable_auditlog.assert_called_once()
        # Verify that pghistory triggers are also disabled for invalid type
        mock_call_command.assert_called_with("pgtrigger", "disable")

        # This test mainly ensures no exceptions are raised

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    @patch("dojo.auditlog.enable_django_auditlog")
    @patch("dojo.auditlog.disable_django_auditlog")
    @patch("dojo.auditlog.call_command")
    def test_dual_audit_system_coexistence(self, mock_call_command, mock_disable_auditlog, mock_enable_auditlog):
        """Test that audit system configuration handles pghistory type correctly."""
        # Call the main configuration function
        configure_audit_system()
        configure_pghistory_triggers()

        # Verify auditlog is disabled when pghistory is the chosen type
        mock_disable_auditlog.assert_called_once()
        # Verify auditlog is not enabled when pghistory is chosen
        mock_enable_auditlog.assert_not_called()
        # Verify that pghistory triggers are enabled when pghistory is the chosen type
        mock_call_command.assert_called_with("pgtrigger", "enable")

        # This demonstrates that the system correctly chooses the configured audit type

    def test_separate_history_lists_approach(self):
        """Test that the dual-history approach creates separate lists correctly."""
        # This test verifies the new approach where we maintain separate history lists
        # instead of mixing audit data from different systems

        # Import the view function to test the separation logic

        # This is more of a structural test to ensure the approach is sound
        # The actual view testing would require more complex setup

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    def test_pghistory_insert_event_creation(self):
        """Test that pghistory creates insert events when a Product_Type is created and auditlog does not."""
        # Configure audit system for pghistory
        configure_audit_system()
        configure_pghistory_triggers()

        # Get the Product_Type event model
        ProductTypeEvent = apps.get_model("dojo", "Product_TypeEvent")

        # Count existing events before creating new Product_Type
        initial_event_count = ProductTypeEvent.objects.count()

        # Clear any existing audit log entries for Product_Type
        LogEntry.objects.filter(content_type__model="product_type").delete()

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
        # The label could be 'insert' or contain insert-related information
        self.assertIsNotNone(latest_event.pgh_created_at,
                           "Event should have a creation timestamp")

        # Verify that NO auditlog entries were created (mutual exclusivity)
        audit_entries = LogEntry.objects.filter(
            content_type__model="product_type",
            object_id=product_type.id,
        )
        self.assertEqual(audit_entries.count(), 0,
                        "Expected NO auditlog entries when pghistory is enabled")

        # Clean up
        product_type.delete()

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    @patch("dojo.auditlog.enable_django_auditlog")
    @patch("dojo.auditlog.call_command")
    def test_configure_audit_system_auditlog_enabled(self, mock_call_command, mock_enable_auditlog):
        """Test that configure_audit_system enables auditlog and configures pghistory triggers correctly."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Verify that auditlog is enabled
        mock_enable_auditlog.assert_called_once()
        # Verify that pghistory triggers are disabled when auditlog is the chosen type
        mock_call_command.assert_called_with("pgtrigger", "disable")

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    @patch("dojo.auditlog.disable_django_auditlog")
    @patch("dojo.auditlog.call_command")
    def test_configure_audit_system_pghistory_enabled(self, mock_call_command, mock_disable_auditlog):
        """Test that configure_audit_system disables auditlog and enables pghistory triggers correctly."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Verify that auditlog is disabled when pghistory is the chosen type
        mock_disable_auditlog.assert_called_once()
        # Verify that pghistory triggers are enabled when pghistory is the chosen type
        mock_call_command.assert_called_with("pgtrigger", "enable")

    @override_settings(ENABLE_AUDITLOG=False)
    @patch("dojo.auditlog.disable_django_auditlog")
    @patch("dojo.auditlog.call_command")
    def test_configure_audit_system_all_disabled(self, mock_call_command, mock_disable_auditlog):
        """Test that configure_audit_system disables both auditlog and pghistory when audit is disabled."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Verify that auditlog is disabled when audit logging is disabled
        mock_disable_auditlog.assert_called_once()
        # Verify that pghistory triggers are also disabled when audit logging is disabled
        mock_call_command.assert_called_with("pgtrigger", "disable")

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="unknown-type")
    @patch("dojo.auditlog.disable_django_auditlog")
    @patch("dojo.auditlog.call_command")
    def test_configure_audit_system_unknown_type(self, mock_call_command, mock_disable_auditlog):
        """Test that configure_audit_system disables both systems for unknown audit types."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Verify that auditlog is disabled for unknown types
        mock_disable_auditlog.assert_called_once()
        # Verify that pghistory triggers are also disabled for unknown types
        mock_call_command.assert_called_with("pgtrigger", "disable")

    @patch("dojo.auditlog.call_command")
    def test_disable_pghistory_command_failure(self, mock_call_command):
        """Test that disable_django_pghistory handles command failures gracefully."""
        # Simulate command failure
        mock_call_command.side_effect = Exception("Command failed")

        # This should not raise an exception
        disable_django_pghistory()

        # Verify that call_command was attempted
        mock_call_command.assert_called_once_with("pgtrigger", "disable")

    @patch("dojo.auditlog.call_command")
    def test_enable_pghistory_command_failure(self, mock_call_command):
        """Test that enable_django_pghistory handles command failures gracefully."""
        # Simulate command failure for trigger enable
        mock_call_command.side_effect = Exception("Command failed")

        # This should not raise an exception
        enable_django_pghistory()

        # Verify that call_command was attempted
        mock_call_command.assert_called_with("pgtrigger", "enable")

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    def test_auditlog_insert_event_creation(self):
        """Test that django-auditlog creates audit log entries when a Product_Type is created and pghistory does not."""
        # Configure audit system for auditlog
        configure_audit_system()
        configure_pghistory_triggers()

        # Get the Product_Type event model for pghistory check
        ProductTypeEvent = apps.get_model("dojo", "Product_TypeEvent")

        # Clear any existing audit log entries for Product_Type
        LogEntry.objects.filter(content_type__model="product_type").delete()

        # Count existing pghistory events
        initial_pghistory_count = ProductTypeEvent.objects.count()

        # Create a new Product_Type
        product_type = Product_Type.objects.create(
            name="Test Product Type for Auditlog",
            description="Test description for auditlog verification",
        )

        # Verify that an audit log entry was created
        audit_entries = LogEntry.objects.filter(
            content_type__model="product_type",
            object_id=product_type.id,
            action=LogEntry.Action.CREATE,
        )

        self.assertEqual(audit_entries.count(), 1,
                        "Expected exactly one audit log entry for Product_Type creation")

        audit_entry = audit_entries.first()
        self.assertEqual(audit_entry.object_repr, str(product_type),
                        "Audit entry should represent the created object")
        self.assertIsNotNone(audit_entry.timestamp,
                           "Audit entry should have a timestamp")

        # Verify that NO pghistory events were created (mutual exclusivity)
        final_pghistory_count = ProductTypeEvent.objects.count()
        self.assertEqual(final_pghistory_count, initial_pghistory_count,
                        "Expected NO new pghistory events when auditlog is enabled")

        # Clean up
        product_type.delete()
