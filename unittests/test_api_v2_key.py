from django.test import TestCase, override_settings
from django.urls import reverse

from dojo.models import Dojo_User
from dojo.user.authentication import token_expires_at
from rest_framework.authtoken.models import Token

USERNAME = "api_key_prg_user"
PASSWORD = "Unused-Pass-1234!"


@override_settings(API_TOKENS_ENABLED=True)
class APIKeyPageTest(TestCase):

    """The API key page must show the generated key and not re-rotate on browser refresh.

    Regression for the API key UX reported in GH issue 14933: the POST branch rendered
    the page directly, so `key` stayed empty (the POST path never loaded the new token),
    and a browser refresh resubmitted the POST, generating yet another key. The redirect
    after the validated POST fixes both: the refreshed request is a GET, which fetches
    (and displays) the token that was just written.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create_user(username=USERNAME, password=PASSWORD)

    def setUp(self):
        self.client.force_login(self.user)

    def _post_generate_key(self):
        return self.client.post(reverse("api_v2_key"), {"id": self.user.id})

    def test_issuing_token_on_first_page_visit_does_not_redirect(self):
        # The GET branch lazily mints the token for an account without one.
        response = self.client.get(reverse("api_v2_key"))
        self.assertEqual(200, response.status_code, response.content[:300])
        self.assertTrue(Token.objects.filter(user=self.user).exists())

    def test_post_returns_redirect_and_follow_up_get_shows_the_new_key(self):
        self.client.get(reverse("api_v2_key"))  # lazily mint the first token
        first_key = Token.objects.get(user=self.user)

        response = self._post_generate_key()
        self.assertEqual(302, response.status_code)
        self.assertEqual(reverse("api_v2_key"), response["Location"])

        # The redirect target is a GET, which loads the new token and renders it.
        second_key = Token.objects.get(user=self.user)
        self.assertNotEqual(first_key.key, second_key.key)

        page = self.client.get(reverse("api_v2_key"))
        self.assertEqual(200, page.status_code, page.content[:300])
        self.assertIn(second_key.key.encode(), page.content)

    def test_browser_refresh_after_generate_shows_the_same_key_no_new_rotation(self):
        # What a single refresh does after the form POST: GET the page again.
        self._post_generate_key()
        generated_key = Token.objects.get(user=self.user)

        refreshed_page = self.client.get(reverse("api_v2_key"))
        self.assertEqual(200, refreshed_page.status_code, refreshed_page.content[:300])
        self.assertIn(generated_key.key.encode(), refreshed_page.content)

        # No hidden extra rotation happened on the follow-up.
        self.assertEqual(1, Token.objects.filter(user=self.user).count())
        self.assertEqual(
            token_expires_at(generated_key),
            token_expires_at(Token.objects.get(user=self.user)),
        )

    def test_success_message_survives_the_redirect(self):
        response = self._post_generate_key()
        follow_up = self.client.get(response["Location"])
        self.assertContains(follow_up, "API Key generated successfully.", status_code=200)
