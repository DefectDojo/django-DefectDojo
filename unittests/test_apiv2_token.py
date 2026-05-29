from datetime import timedelta

from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import User, UserContactInfo
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class ApiTokenTest(APITestCase):

    """Test the ApiToken APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def _create_user(self, username):
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": username,
            "email": f"{username}@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user = User.objects.get(id=r.json()["id"])
        token = Token.objects.get_or_create(user=user)[0]
        return user, token, password

    def _client_for(self, token_key):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token_key)
        return client

    def test_api_token_list_superuser_sees_all(self):
        r = self.client.get(reverse("api-token-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        results = r.json()["results"]
        self.assertGreaterEqual(len(results), 1)
        for item in results:
            for field in ["user_id", "username", "created", "expiry"]:
                self.assertIn(field, item)
            self.assertNotIn("key", item)

    def test_api_token_list_non_superuser_sees_only_own(self):
        user, token, _ = self._create_user("api-token-list-user")
        client = self._client_for(token.key)

        r = client.get(reverse("api-token-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        results = r.json()["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["user_id"], user.id)

    def test_api_token_retrieve_other_user_non_superuser_returns_404(self):
        _user1, token1, _ = self._create_user("api-token-retrieve-user1")
        user2, _, _ = self._create_user("api-token-retrieve-user2")
        client = self._client_for(token1.key)

        r = client.get("{}{}/".format(reverse("api-token-list"), user2.id))
        self.assertEqual(r.status_code, 404, r.content[:1000])

    def test_api_token_revoke_as_superuser(self):
        user, _, _ = self._create_user("api-token-revoke-super")

        r = self.client.delete("{}{}/".format(reverse("api-token-list"), user.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])
        self.assertFalse(Token.objects.filter(user=user).exists())

    def test_api_token_revoke_own(self):
        user, token, _ = self._create_user("api-token-revoke-self")
        client = self._client_for(token.key)

        r = client.delete("{}{}/".format(reverse("api-token-list"), user.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])
        self.assertFalse(Token.objects.filter(user=user).exists())

    def test_api_token_revoke_clears_expiry(self):
        user, _, _ = self._create_user("api-token-revoke-expiry")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        uci.token_expiry = timezone.now() + timedelta(days=30)
        uci.save(update_fields=["token_expiry"])

        r = self.client.delete("{}{}/".format(reverse("api-token-list"), user.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])

        uci.refresh_from_db()
        self.assertIsNone(uci.token_expiry)

    def test_expired_token_rejected(self):
        user, token, _ = self._create_user("api-token-expired")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        uci.token_expiry = timezone.now() - timedelta(days=1)
        uci.save(update_fields=["token_expiry"])

        client = self._client_for(token.key)
        r = client.get(reverse("user-list"))
        self.assertEqual(r.status_code, 403, r.content[:1000])
        self.assertIn("API token has expired.", r.content.decode("utf-8"))

    def test_user_serializer_exposes_token_expiry(self):
        user, _, _ = self._create_user("api-token-user-serializer")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        expiry = timezone.now() + timedelta(days=14)
        uci.token_expiry = expiry
        uci.save(update_fields=["token_expiry"])

        r = self.client.get("{}{}/".format(reverse("user-list"), user.id))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        body = r.json()
        self.assertIn("token_expiry", body)
        self.assertIsNotNone(body["token_expiry"])

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=7)
    def test_default_expiry_applied_on_reset(self):
        user, _, _ = self._create_user("api-token-expiry-default")

        r = self.client.post("{}{}/reset_api_token/".format(reverse("user-list"), user.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])

        uci = UserContactInfo.objects.get(user=user)
        self.assertIsNotNone(uci.token_expiry)
        expected = timezone.now() + timedelta(days=7)
        self.assertLess(abs((expected - uci.token_expiry).total_seconds()), 30)

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=0)
    def test_no_expiry_when_default_is_zero(self):
        user, _, _ = self._create_user("api-token-no-expiry")

        r = self.client.post("{}{}/reset_api_token/".format(reverse("user-list"), user.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])

        uci = UserContactInfo.objects.get(user=user)
        self.assertIsNone(uci.token_expiry)
