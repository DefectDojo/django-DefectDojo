from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse

from dojo.models import System_Settings
from unittests.dojo_test_case import DojoTestCase

User = get_user_model()


# Regression: watson_searchentry grew to 44 GB while nothing in the Pro UI reads it.
# The legacy /simple_search page is watson's only reader, so when watson is disabled
# (DD_WATSON_SEARCH_ENABLED=False) the view must stop serving instead of calling
# watson.filter/search on models that were never registered.
#
# V3_FEATURE_LOCATIONS is pinned off so this matches OSS CI defaults (the deprecated
# Endpoint model raises under V3, which is unrelated to what we assert here).
@override_settings(SECURE_SSL_REDIRECT=False, V3_FEATURE_LOCATIONS=False)
class TestSimpleSearchWatsonToggle(DojoTestCase):

    def setUp(self):
        System_Settings.objects.get_or_create(id=1)
        super().setUp()
        self.user = User.objects.create_superuser("watson-toggle-admin", "wt@example.com", "password")

    def _get_simple_search(self):
        self.client.force_login(self.user)
        return self.client.get(reverse("simple_search"), {"query": "test"})

    @override_settings(WATSON_SEARCH_ENABLED=False)
    def test_simple_search_gone_when_watson_disabled(self):
        response = self._get_simple_search()
        self.assertEqual(
            response.status_code, 410,
            msg=f"expected 410 Gone when WATSON_SEARCH_ENABLED=False, got {response.status_code}",
        )

    @override_settings(WATSON_SEARCH_ENABLED=True)
    def test_simple_search_available_when_watson_enabled(self):
        response = self._get_simple_search()
        self.assertEqual(
            response.status_code, 200,
            msg=f"expected 200 when WATSON_SEARCH_ENABLED=True, got {response.status_code}",
        )
