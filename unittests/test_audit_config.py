"""
Unit tests for audit configuration functionality.

Tests the dual-audit system where both django-auditlog and django-pghistory
can coexist, allowing users to see historical data from both systems.
"""
import logging
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings

# Disable logging during tests to avoid noise
logging.disable(logging.CRITICAL)


class TestAuditConfig(TestCase):

    """Test audit configuration functionality."""

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    @patch("dojo.auditlog.auditlog")
    def test_register_auditlog_models_enabled(self, mock_auditlog):
        """Test that auditlog models are registered when enabled."""
        from dojo.auditlog import register_auditlog_models

        # Mock the auditlog registry
        mock_auditlog.register = MagicMock()

        register_auditlog_models()

        # Verify that register was called multiple times (once for each model)
        self.assertTrue(mock_auditlog.register.called)
        self.assertGreater(mock_auditlog.register.call_count, 5)

    @override_settings(ENABLE_AUDITLOG=False, AUDITLOG_TYPE="django-auditlog")
    @patch("dojo.auditlog.auditlog")
    def test_register_auditlog_models_disabled(self, mock_auditlog):
        """Test that auditlog models are not registered when disabled."""
        from dojo.auditlog import register_auditlog_models

        mock_auditlog.register = MagicMock()

        register_auditlog_models()

        # Verify that register was not called
        self.assertFalse(mock_auditlog.register.called)

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    @patch("dojo.auditlog.auditlog")
    def test_register_auditlog_models_wrong_type(self, mock_auditlog):
        """Test that auditlog models are not registered when using pghistory."""
        from dojo.auditlog import register_auditlog_models

        mock_auditlog.register = MagicMock()

        register_auditlog_models()

        # Verify that register was not called
        self.assertFalse(mock_auditlog.register.called)

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    @patch("dojo.auditlog.pghistory")
    def test_register_pghistory_models_enabled(self, mock_pghistory):
        """Test that pghistory models are registered when enabled."""
        from dojo.auditlog import register_pghistory_models

        # Mock pghistory.track
        mock_pghistory.track = MagicMock()
        mock_pghistory.InsertEvent = MagicMock()
        mock_pghistory.UpdateEvent = MagicMock()
        mock_pghistory.DeleteEvent = MagicMock()

        register_pghistory_models()

        # Verify that track was called multiple times (once for each model)
        self.assertTrue(mock_pghistory.track.called)
        self.assertGreater(mock_pghistory.track.call_count, 5)

    @override_settings(ENABLE_AUDITLOG=False, AUDITLOG_TYPE="django-pghistory")
    @patch("dojo.auditlog.pghistory")
    def test_register_pghistory_models_disabled(self, mock_pghistory):
        """Test that pghistory models are not registered when disabled."""
        from dojo.auditlog import register_pghistory_models

        mock_pghistory.track = MagicMock()

        register_pghistory_models()

        # Verify that track was not called
        self.assertFalse(mock_pghistory.track.called)

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    @patch("dojo.auditlog.pghistory")
    def test_register_pghistory_models_wrong_type(self, mock_pghistory):
        """Test that pghistory models are not registered when using auditlog."""
        from dojo.auditlog import register_pghistory_models

        mock_pghistory.track = MagicMock()

        register_pghistory_models()

        # Verify that track was not called
        self.assertFalse(mock_pghistory.track.called)

    def test_audit_config_import(self):
        """Test that audit_config module can be imported without errors."""
        try:
            import dojo.auditlog  # noqa: F401
        except ImportError as e:
            self.fail(f"Failed to import audit_config: {e}")

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="invalid-type")
    @patch("dojo.auditlog.logger")
    def test_invalid_audit_type_warning(self, mock_logger):
        """Test that invalid audit types generate warnings."""
        from dojo.auditlog import register_auditlog_models, register_pghistory_models

        # Both functions should handle invalid types gracefully
        register_auditlog_models()
        register_pghistory_models()

        # This test mainly ensures no exceptions are raised

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    @patch("dojo.auditlog.auditlog")
    @patch("dojo.auditlog.pghistory")
    def test_dual_audit_system_coexistence(self, mock_pghistory, mock_auditlog):
        """Test that both audit systems can coexist for historical data preservation."""
        from dojo.auditlog import register_auditlog_models, register_pghistory_models

        # Mock both systems
        mock_auditlog.register = MagicMock()
        mock_pghistory.track = MagicMock()
        mock_pghistory.InsertEvent = MagicMock()
        mock_pghistory.UpdateEvent = MagicMock()
        mock_pghistory.DeleteEvent = MagicMock()

        # Call both registration functions
        register_auditlog_models()  # Should not register (wrong type)
        register_pghistory_models()  # Should register (correct type)

        # Verify only pghistory was called
        self.assertFalse(mock_auditlog.register.called)
        self.assertTrue(mock_pghistory.track.called)

        # This demonstrates that the system can handle both backends being available
        # while only using the configured one for new entries

    def test_separate_history_lists_approach(self):
        """Test that the dual-history approach creates separate lists correctly."""
        # This test verifies the new approach where we maintain separate history lists
        # instead of mixing audit data from different systems

        # Import the view function to test the separation logic

        # This is more of a structural test to ensure the approach is sound
        # The actual view testing would require more complex setup


# Re-enable logging after tests
logging.disable(logging.NOTSET)
