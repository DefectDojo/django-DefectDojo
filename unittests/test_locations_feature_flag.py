"""
Unit tests for the ``dojo.location.feature`` runtime accessor.

The accessor turns ``V3_FEATURE_LOCATIONS`` into a call-time lookup that Pro can
override with a database-backed resolver. Open source keeps reading the Django
setting live, so these tests assert both the default (setting-driven) behaviour
and the register-with-override hook semantics.
"""

from django.test import SimpleTestCase, override_settings

from dojo.location import feature
from dojo.location.feature import locations_enabled, register_locations_resolver


class LocationsFeatureAccessorTest(SimpleTestCase):
    def setUp(self):
        # Each test starts with no resolver registered; restore afterwards so a
        # test cannot leak a resolver into the rest of the suite.
        self._saved_resolver = feature._RESOLVER["fn"]
        feature._RESOLVER["fn"] = None
        self.addCleanup(self._restore_resolver)

    def _restore_resolver(self):
        feature._RESOLVER["fn"] = self._saved_resolver

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_default_reads_setting_true(self):
        self.assertTrue(locations_enabled())

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_default_reads_setting_false(self):
        self.assertFalse(locations_enabled())

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_registered_resolver_overrides_setting(self):
        register_locations_resolver(lambda: False, override=True)
        # Resolver wins over the (True) setting.
        self.assertFalse(locations_enabled())

    def test_default_does_not_clobber_without_override(self):
        register_locations_resolver(lambda: True)
        register_locations_resolver(lambda: False)  # no override -> ignored
        self.assertTrue(locations_enabled())

    def test_override_replaces_existing_resolver(self):
        register_locations_resolver(lambda: True)
        register_locations_resolver(lambda: False, override=True)
        self.assertFalse(locations_enabled())

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_resolver_failure_falls_back_to_setting(self):
        def _boom():
            msg = "resolver unavailable"
            raise RuntimeError(msg)

        register_locations_resolver(_boom, override=True)
        # Boot-safety: any resolver failure falls back to the live setting.
        self.assertTrue(locations_enabled())
