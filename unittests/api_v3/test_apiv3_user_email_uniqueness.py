# Regression: user create and update accepted an email another account already held.
from django.test import override_settings

from dojo.models import Dojo_User

from .base import ApiV3TestCase


@override_settings(SECURE_SSL_REDIRECT=False)
class TestApiV3UserEmailUniqueness(ApiV3TestCase):

    """v3 user create, update and replace refuse a new email another account holds, ignoring case."""

    def setUp(self):
        super().setUp()
        self.holder = Dojo_User.objects.create(username="v3_uniq_holder", email="holder@example.com")
        self.other = Dojo_User.objects.create(username="v3_uniq_other", email="other@example.com")

    def test_create_refuses_a_taken_email(self):
        response = self.client.post(
            self.v3_url("users"),
            {"username": "v3_uniq_new", "email": "HOLDER@example.com", "password": "Not-a-secret-1!xY"},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(Dojo_User.objects.filter(username="v3_uniq_new").exists())

    def test_update_and_replace_refuse_a_taken_email(self):
        url = self.v3_url(f"users/{self.other.pk}")
        patched = self.client.patch(url, {"email": "Holder@example.com"}, format="json")
        self.assertEqual(patched.status_code, 400, patched.content)
        replaced = self.client.put(url, {"username": "v3_uniq_other", "email": "holder@EXAMPLE.com"}, format="json")
        self.assertEqual(replaced.status_code, 400, replaced.content)
        persisted = Dojo_User.objects.get(pk=self.other.pk).email
        self.assertEqual(persisted, "other@example.com", msg=f"persisted={persisted}")

    def test_update_keeps_an_already_shared_email(self):
        Dojo_User.objects.filter(pk=self.other.pk).update(email="HOLDER@example.com")
        response = self.client.patch(
            self.v3_url(f"users/{self.other.pk}"), {"first_name": "Kept", "email": "HOLDER@example.com"}, format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
