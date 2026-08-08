from datetime import timedelta

from crum import impersonate
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import User, UserContactInfo
from dojo.user.authentication import token_expires_at, token_is_expired
from dojo.user.ui.forms import UserContactInfoForm
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class ApiTokenTest(APITestCase):

    """Test API token expiry enforcement and the revoke-by-key endpoint."""

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

    def _revoke_url(self):
        return reverse("api-token-revoke")

    def _set_created(self, token, when):
        """``Token.created`` is auto_now_add, so it can only be backdated after insert."""
        Token.objects.filter(pk=token.pk).update(created=when)
        token.refresh_from_db()
        return token

    # --- revoke ---

    def test_revoke_by_key_as_superuser(self):
        user, token, _ = self._create_user("api-token-revoke-super")

        r = self.client.post(self._revoke_url(), {"key": token.key}, format="json")
        self.assertEqual(r.status_code, 204, r.content[:1000])
        self.assertFalse(Token.objects.filter(user=user).exists())

    def test_revoke_by_key_clears_explicit_expiry(self):
        """A stale override would otherwise expire the user's next token on arrival."""
        user, token, _ = self._create_user("api-token-revoke-expiry")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        uci.token_expiry = timezone.now() + timedelta(days=30)
        uci.save(update_fields=["token_expiry"])

        r = self.client.post(self._revoke_url(), {"key": token.key}, format="json")
        self.assertEqual(r.status_code, 204, r.content[:1000])

        uci.refresh_from_db()
        self.assertIsNone(uci.token_expiry)

    def test_revoke_unknown_key_returns_404(self):
        r = self.client.post(self._revoke_url(), {"key": "notarealtoken"}, format="json")
        self.assertEqual(r.status_code, 404, r.content[:1000])

    def test_revoke_requires_a_key(self):
        for payload in ({}, {"key": ""}, {"key": "   "}):
            r = self.client.post(self._revoke_url(), payload, format="json")
            self.assertEqual(r.status_code, 400, r.content[:1000])

    def test_revoke_by_key_non_superuser_forbidden(self):
        _user, token, _ = self._create_user("api-token-revoke-nonsuperuser")
        client = self._client_for(token.key)

        r = client.post(self._revoke_url(), {"key": token.key}, format="json")
        self.assertEqual(r.status_code, 403, r.content[:1000])

    def test_revoke_by_key_unauthenticated_forbidden(self):
        _user, token, _ = self._create_user("api-token-revoke-anon")

        r = APIClient().post(self._revoke_url(), {"key": token.key}, format="json")
        self.assertIn(r.status_code, (401, 403), r.content[:1000])
        self.assertTrue(Token.objects.filter(key=token.key).exists())

    # --- expiry enforcement ---

    def test_expired_token_rejected(self):
        user, token, _ = self._create_user("api-token-expired")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        uci.token_expiry = timezone.now() - timedelta(days=1)
        uci.save(update_fields=["token_expiry"])

        client = self._client_for(token.key)
        r = client.get(reverse("user-list"))
        self.assertEqual(r.status_code, 403, r.content[:1000])
        self.assertIn("API token has expired.", r.content.decode("utf-8"))

    def test_unexpired_token_accepted(self):
        user, token, _ = self._create_user("api-token-unexpired")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        uci.token_expiry = timezone.now() + timedelta(days=1)
        uci.save(update_fields=["token_expiry"])

        r = self._client_for(token.key).get(reverse("user_profile"))
        self.assertEqual(r.status_code, 200, r.content[:1000])

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=7)
    def test_explicit_expiry_overrides_the_instance_default(self):
        user, token, _ = self._create_user("api-token-override")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        explicit = timezone.now() + timedelta(days=365)
        uci.token_expiry = explicit
        uci.save(update_fields=["token_expiry"])

        token.refresh_from_db()
        self.assertEqual(token_expires_at(token), explicit)

    # --- the instance-wide default applies to every token, however it was minted ---

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=30)
    def test_default_expiry_is_measured_from_token_creation(self):
        _user, token, _ = self._create_user("api-token-default-window")

        self.assertFalse(token_is_expired(token))
        expected = token.created + timedelta(days=30)
        self.assertEqual(token_expires_at(token), expected)

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=30)
    def test_default_expiry_rejects_a_token_older_than_the_window(self):
        _user, token, _ = self._create_user("api-token-default-aged")
        self._set_created(token, timezone.now() - timedelta(days=31))

        r = self._client_for(token.key).get(reverse("user-list"))
        self.assertEqual(r.status_code, 403, r.content[:1000])
        self.assertIn("API token has expired.", r.content.decode("utf-8"))

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=30)
    def test_default_expiry_covers_tokens_minted_by_the_auth_endpoint(self):
        """
        Regression: the default must not be bypassable.

        Tokens are minted by three separate paths. If the default were stamped onto the user at
        rotation time rather than derived from the token, anyone could obtain a token with no
        expiry by going through ``api-token-auth`` instead of a reset.
        """
        user, token, password = self._create_user("api-token-authendpoint")
        token.delete()

        r = APIClient().post(
            reverse("api-token-auth"), {"username": user.username, "password": password}, format="json",
        )
        self.assertEqual(r.status_code, 200, r.content[:1000])

        minted = Token.objects.get(user=user)
        self.assertIsNotNone(token_expires_at(minted))

        self._set_created(minted, timezone.now() - timedelta(days=31))
        r = self._client_for(minted.key).get(reverse("user-list"))
        self.assertEqual(r.status_code, 403, r.content[:1000])

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=0)
    def test_no_expiry_when_default_is_zero(self):
        _user, token, _ = self._create_user("api-token-no-expiry")

        self.assertIsNone(token_expires_at(token))
        self.assertFalse(token_is_expired(token))

    @override_settings(API_TOKEN_DEFAULT_EXPIRY_DAYS=7)
    def test_reset_clears_a_stale_override_so_the_new_token_is_usable(self):
        """A past override left in place would kill the replacement token immediately."""
        user, _token, _ = self._create_user("api-token-reset-clears")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        uci.token_expiry = timezone.now() - timedelta(days=1)
        uci.save(update_fields=["token_expiry"])

        r = self.client.post("{}{}/reset_api_token/".format(reverse("user-list"), user.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])

        uci.refresh_from_db()
        self.assertIsNone(uci.token_expiry)

        new_token = Token.objects.get(user=user)
        self.assertFalse(token_is_expired(new_token))
        self.assertEqual(token_expires_at(new_token), new_token.created + timedelta(days=7))

    # --- serializer ---

    def test_user_serializer_exposes_token_expiry(self):
        user, _, _ = self._create_user("api-token-user-serializer")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        uci.token_expiry = timezone.now() + timedelta(days=14)
        uci.save(update_fields=["token_expiry"])

        r = self.client.get("{}{}/".format(reverse("user-list"), user.id))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        body = r.json()
        self.assertIn("token_expiry", body)
        self.assertIsNotNone(body["token_expiry"])

    # --- a user must not be able to lift their own expiry ---

    def test_profile_form_cannot_change_token_expiry(self):
        """
        Regression: ``UserContactInfoForm`` is the self-service profile form and its Meta only
        excludes ``user``/``slack_user_id``, so a new model field lands on it as editable. Token
        expiry is a security control; setting it is reserved for superusers via the API.
        """
        user, _token, _ = self._create_user("api-token-selfedit")
        uci, _ = UserContactInfo.objects.get_or_create(user=user)
        original = timezone.now() - timedelta(days=1)
        uci.token_expiry = original
        uci.save(update_fields=["token_expiry"])

        with impersonate(user):
            form = UserContactInfoForm(instance=uci, user=user)
            self.assertTrue(form.fields["token_expiry"].disabled)

            posted = {
                "title": "", "phone_number": "", "cell_number": "",
                "twitter_username": "", "github_username": "", "slack_username": "",
                "token_expiry": (timezone.now() + timedelta(days=3650)).isoformat(),
            }
            bound = UserContactInfoForm(data=posted, instance=uci, user=user)
            bound.is_valid()
            self.assertEqual(bound.cleaned_data.get("token_expiry"), original)

        uci.refresh_from_db()
        self.assertEqual(uci.token_expiry, original)
