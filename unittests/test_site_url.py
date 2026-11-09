"""Unit tests for ``dojo.site_url``, the helper absolute URLs are built from."""

from django.test import SimpleTestCase, override_settings

from dojo import site_url as site_url_module
from dojo.site_url import absolute_url, default_site_url, register_site_url_resolver, site_url
from dojo.utils import get_full_url, get_site_url


class SiteUrlHelperTest(SimpleTestCase):
    def setUp(self):
        # Each test starts with no resolver registered and restores the previous one,
        # so a test cannot leak a resolver into the rest of the suite.
        saved = site_url_module._RESOLVER["fn"]
        site_url_module._RESOLVER["fn"] = None
        self.addCleanup(site_url_module._RESOLVER.__setitem__, "fn", saved)

    @override_settings(SITE_URL="https://dojo.example.com")
    def test_default_reads_setting_live(self):
        self.assertEqual("https://dojo.example.com", site_url())
        with override_settings(SITE_URL="https://other.example.com"):
            self.assertEqual("https://other.example.com", site_url())

    @override_settings(SITE_URL="https://dojo.example.com/")
    def test_default_keeps_the_setting_verbatim(self):
        # No trailing-slash normalization: the value is exactly what get_site_url returned.
        self.assertEqual("https://dojo.example.com/", site_url())

    @override_settings(SITE_URL="")
    def test_empty_setting_returns_placeholder_and_warns(self):
        with self.assertLogs("dojo.utils", level="WARNING") as logs:
            self.assertEqual("settings.SITE_URL", site_url())
        self.assertIn("SITE URL undefined in settings", logs.output[0])

    @override_settings(SITE_URL="https://dojo.example.com")
    def test_absolute_url_prefixes_path(self):
        self.assertEqual("https://dojo.example.com/finding/7", absolute_url("/finding/7"))

    @override_settings(SITE_URL="https://dojo.example.com")
    def test_registered_resolver_overrides_setting(self):
        register_site_url_resolver(lambda: "https://registered.example.com", override=True)
        self.assertEqual("https://registered.example.com", site_url())
        self.assertEqual("https://registered.example.com/test/3", absolute_url("/test/3"))
        # The default stays reachable for a resolver that wants to delegate to it.
        self.assertEqual("https://dojo.example.com", default_site_url())

    def test_register_without_override_keeps_existing(self):
        register_site_url_resolver(lambda: "https://first.example.com")
        register_site_url_resolver(lambda: "https://second.example.com")
        self.assertEqual("https://first.example.com", site_url())

    def test_register_with_override_replaces_existing(self):
        register_site_url_resolver(lambda: "https://first.example.com")
        register_site_url_resolver(lambda: "https://second.example.com", override=True)
        self.assertEqual("https://second.example.com", site_url())

    @override_settings(SITE_URL="https://dojo.example.com")
    def test_resolver_error_propagates(self):
        def broken():
            msg = "resolver failed"
            raise RuntimeError(msg)

        register_site_url_resolver(broken, override=True)
        with self.assertRaisesMessage(RuntimeError, "resolver failed"):
            site_url()

    @override_settings(SITE_URL="https://dojo.example.com")
    def test_legacy_utils_helpers_delegate(self):
        self.assertEqual("https://dojo.example.com", get_site_url())
        self.assertEqual("https://dojo.example.com/engagement/2", get_full_url("/engagement/2"))
        register_site_url_resolver(lambda: "https://registered.example.com", override=True)
        self.assertEqual("https://registered.example.com", get_site_url())
        self.assertEqual("https://registered.example.com/engagement/2", get_full_url("/engagement/2"))
