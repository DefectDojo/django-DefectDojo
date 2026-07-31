from django.test import override_settings
from django.urls import reverse

from dojo.models import Dojo_User
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

# Each of these used to return a 500. The query string is visitor input and the request
# method is whatever a client decides to send, so neither may reach an unguarded queryset
# or a local the view only assigns on the GET path.
#
# V3_FEATURE_LOCATIONS is pinned off to match OSS CI defaults, as in
# test_simple_search_scoping.py.


@override_settings(SECURE_SSL_REDIRECT=False, V3_FEATURE_LOCATIONS=False, WATSON_SEARCH_ENABLED=True)
@versioned_fixtures
class TestSimpleSearchBadInput(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.client.force_login(Dojo_User.objects.get(username="admin"))
        self.url = reverse("simple_search")

    def test_non_numeric_finding_id_finds_nothing(self):
        response = self.client.get(self.url, {"query": "id:abc"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["findings"])

    def test_unbalanced_quote_still_searches(self):
        response = self.client.get(self.url, {"query": '"unbalanced'})
        self.assertEqual(response.status_code, 200)

    def test_head_request_renders(self):
        # Uptime monitors and link-preview bots send these, and CSRF does not turn a
        # safe method away.
        self.assertEqual(self.client.head(self.url, {"query": "anything"}).status_code, 200)

    def test_options_request_renders(self):
        self.assertEqual(self.client.options(self.url).status_code, 200)
