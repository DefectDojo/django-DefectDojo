import base64

from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Dojo_User, User, UserContactInfo

OLD_PASSWORD = "oldTEST1234!@#$"
NEW_PASSWORD = "newTEST5678!@#$"


class ForcedPasswordResetApiTest(TestCase):

    """The forced-reset flag has to reach the API, and completing the reset has to drop the token."""

    def setUp(self):
        self.user = User.objects.create_user(username="forced-reset-user", password=OLD_PASSWORD)
        self.contact_info = UserContactInfo.objects.create(user=self.user)
        self.anon = APIClient()

    def set_forced_reset(self, *, value):
        self.contact_info.force_password_reset = value
        self.contact_info.save()

    def obtain_token(self):
        return self.anon.post(
            reverse("api-token-auth"),
            {"username": self.user.username, "password": OLD_PASSWORD},
            format="json",
        )

    def change_password(self, current, new):
        client = self.client
        self.assertTrue(client.login(username=self.user.username, password=current))
        return client.post(
            reverse("change_password"),
            {"current_password": current, "new_password": new, "confirm_password": new},
        )

    def test_token_is_not_issued_while_reset_is_pending(self):
        self.set_forced_reset(value=True)

        r = self.obtain_token()

        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertFalse(Token.objects.filter(user=self.user).exists())

    def test_token_is_issued_once_the_reset_is_cleared(self):
        self.set_forced_reset(value=False)

        r = self.obtain_token()

        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertIn("token", r.json())

    def test_completing_the_forced_reset_revokes_the_existing_token(self):
        key = Token.objects.create(user=self.user).key
        self.set_forced_reset(value=True)

        r = self.change_password(OLD_PASSWORD, NEW_PASSWORD)

        self.assertEqual(r.status_code, 302, r.content[:1000])
        self.contact_info.refresh_from_db()
        self.assertFalse(self.contact_info.force_password_reset)
        self.assertFalse(Token.objects.filter(key=key).exists())

    def test_an_ordinary_password_change_keeps_the_token(self):
        key = Token.objects.create(user=self.user).key
        self.set_forced_reset(value=False)

        r = self.change_password(OLD_PASSWORD, NEW_PASSWORD)

        self.assertEqual(r.status_code, 302, r.content[:1000])
        self.assertTrue(Token.objects.filter(key=key).exists())

    def test_a_token_from_before_the_forced_reset_stops_working_after_it(self):
        key = Token.objects.create(user=self.user).key
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {key}")
        self.assertEqual(client.get(reverse("user_profile")).status_code, 200)

        self.set_forced_reset(value=True)
        self.change_password(OLD_PASSWORD, NEW_PASSWORD)

        self.assertEqual(client.get(reverse("user_profile")).status_code, 403)

    def test_disable_force_password_reset_is_a_no_op_when_the_flag_was_never_set(self):
        key = Token.objects.create(user=self.user).key
        self.set_forced_reset(value=False)

        Dojo_User.objects.get(pk=self.user.pk).disable_force_password_reset()

        self.assertTrue(Token.objects.filter(key=key).exists())


class BasicAuthAccountRulesTest(TestCase):

    """HTTP Basic auth on the API follows the same account rules as the token endpoint."""

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username="basic-auth-user", password=OLD_PASSWORD)
        self.contact_info = UserContactInfo.objects.create(user=self.user)

    def tearDown(self):
        cache.clear()

    def _get(self, password):
        client = APIClient()
        credentials = base64.b64encode(f"{self.user.username}:{password}".encode()).decode()
        client.credentials(HTTP_AUTHORIZATION=f"Basic {credentials}")
        return client.get(reverse("user_profile"))

    def test_basic_auth_works_for_an_ordinary_account(self):
        self.assertEqual(200, self._get(OLD_PASSWORD).status_code)

    def test_basic_auth_is_refused_while_a_reset_is_pending(self):
        self.contact_info.force_password_reset = True
        self.contact_info.save()
        self.assertIn(self._get(OLD_PASSWORD).status_code, (401, 403))

    @override_settings(RATE_LIMITER_BLOCK=True, RATE_LIMITER_RATE="2/m")
    def test_failed_attempts_are_limited_when_blocking_is_on(self):
        for _ in range(3):
            self.assertIn(self._get("wrong-password").status_code, (401, 403))
        # Over the limit, even the right password is turned away until the window passes.
        self.assertEqual(429, self._get(OLD_PASSWORD).status_code)

    @override_settings(RATE_LIMITER_BLOCK=True, RATE_LIMITER_RATE="2/m")
    def test_successful_requests_are_not_counted(self):
        for _ in range(5):
            self.assertEqual(200, self._get(OLD_PASSWORD).status_code)

    def test_failed_attempts_are_not_limited_by_default(self):
        for _ in range(10):
            self.assertIn(self._get("wrong-password").status_code, (401, 403))
        self.assertEqual(200, self._get(OLD_PASSWORD).status_code)


class PasswordResetLinkRevokesTokenTest(TestCase):

    """Completing the emailed password reset is account recovery, so it revokes the API token."""

    def setUp(self):
        self.user = User.objects.create_user(username="reset-link-user", password=OLD_PASSWORD, email="reset@example.com")
        UserContactInfo.objects.create(user=self.user)

    def test_reset_link_revokes_the_token(self):
        key = Token.objects.create(user=self.user).key
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        # The first request swaps the token for a session marker and redirects to the set-password form.
        response = self.client.get(reverse("password_reset_confirm", args=(uid, token)), follow=True)
        set_password_url = response.redirect_chain[-1][0]
        response = self.client.post(set_password_url, {"new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD})
        self.assertEqual(302, response.status_code, response.content[:500])
        self.assertFalse(Token.objects.filter(key=key).exists())
