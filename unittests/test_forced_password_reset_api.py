from django.test import TestCase
from django.urls import reverse
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
