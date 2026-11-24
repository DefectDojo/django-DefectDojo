# Regression: any user could set their profile email to any address (another account's, or one they do not own).
import re
from datetime import timedelta
from unittest import mock

from crum import impersonate
from django.contrib.auth.models import Permission
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from dojo.models import Dojo_User, System_Settings
from dojo.user.ui.forms import AddDojoUserForm, EditDojoUserForm
from unittests.dojo_test_case import DojoTestCase

CONFIRM_LINK = re.compile(r"/profile/email/confirm/(?P<token>[^\s\"'<>]+)")


@override_settings(SECURE_SSL_REDIRECT=False)
class ProfileEmailChangeTest(DojoTestCase):

    """The classic profile page: a non-admin never sets an email it has not proven it owns."""

    @classmethod
    def setUpTestData(cls):
        cls.reader = Dojo_User.objects.create_user(
            username="email_reader", email="reader@example.com", password="Not-a-secret-1!",  # noqa: S106
        )
        cls.victim = Dojo_User.objects.create_user(
            username="email_victim", email="victim@example.com", password="Not-a-secret-1!",  # noqa: S106
        )
        cls.superuser = Dojo_User.objects.create_user(
            username="email_super", email="super@example.com", password="Not-a-secret-1!",  # noqa: S106
            is_superuser=True, is_staff=True,
        )

    def setUp(self):
        System_Settings.objects.update(enable_user_profile_editable=True)

    def _post_profile(self, user, **overrides):
        self.client.force_login(user)
        data = {"first_name": user.first_name, "last_name": user.last_name, "email": user.email}
        data.update(overrides)
        return self.client.post(reverse("view_profile"), data)

    def _email_of(self, user):
        return Dojo_User.objects.get(pk=user.pk).email

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=True)
    def test_reader_cannot_take_another_accounts_email(self):
        for submitted in ("victim@example.com", "VICTIM@Example.com"):
            self._post_profile(self.reader, email=submitted)
            persisted = self._email_of(self.reader)
            self.assertEqual(persisted, "reader@example.com", msg=f"submitted={submitted}, persisted={persisted}")
        self.assertEqual(mail.outbox, [], msg="no confirmation is sent for an address another account holds")

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=False)
    def test_without_confirmation_a_reader_cannot_change_own_email(self):
        self._post_profile(self.reader, email="fresh@example.com")
        persisted = self._email_of(self.reader)
        self.assertEqual(persisted, "reader@example.com", msg=f"persisted={persisted}")
        self.assertEqual(mail.outbox, [])

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=False)
    def test_without_confirmation_other_profile_fields_still_save(self):
        self._post_profile(self.reader, first_name="Renamed")
        self.assertEqual(Dojo_User.objects.get(pk=self.reader.pk).first_name, "Renamed")

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=True)
    def test_with_confirmation_the_email_changes_only_after_the_link(self):
        self._post_profile(self.reader, email="fresh@example.com")
        persisted = self._email_of(self.reader)
        self.assertEqual(persisted, "reader@example.com", msg=f"old email stays until confirmed, persisted={persisted}")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["fresh@example.com"])
        token = CONFIRM_LINK.search(mail.outbox[0].body).group("token")

        self.client.get(reverse("confirm_email_change", args=(token,)))
        persisted = self._email_of(self.reader)
        self.assertEqual(persisted, "fresh@example.com", msg=f"persisted={persisted}")

        # A used link is rejected: once the address moves on, replaying the old link changes nothing.
        reader = Dojo_User.objects.get(pk=self.reader.pk)
        self._post_profile(reader, email="third@example.com")
        second = CONFIRM_LINK.search(mail.outbox[1].body).group("token")
        self.client.get(reverse("confirm_email_change", args=(second,)))
        self.assertEqual(self._email_of(self.reader), "third@example.com")
        self.client.get(reverse("confirm_email_change", args=(token,)))
        persisted = self._email_of(self.reader)
        self.assertEqual(persisted, "third@example.com", msg=f"a replayed link moved the email back, persisted={persisted}")

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=True)
    def test_an_expired_link_is_rejected(self):
        self._post_profile(self.reader, email="fresh@example.com")
        token = CONFIRM_LINK.search(mail.outbox[0].body).group("token")
        later = timezone.now() + timedelta(days=30)
        with mock.patch("django.core.signing.time.time", return_value=later.timestamp()):
            self.client.get(reverse("confirm_email_change", args=(token,)))
        self.assertEqual(self._email_of(self.reader), "reader@example.com")

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=True)
    def test_a_link_for_another_user_is_rejected(self):
        self._post_profile(self.reader, email="fresh@example.com")
        token = CONFIRM_LINK.search(mail.outbox[0].body).group("token")
        self.client.force_login(self.victim)
        self.client.get(reverse("confirm_email_change", args=(token,)))
        self.assertEqual(self._email_of(self.reader), "reader@example.com")
        self.assertEqual(self._email_of(self.victim), "victim@example.com")

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=True)
    def test_link_is_rejected_when_the_address_was_taken_meanwhile(self):
        self._post_profile(self.reader, email="fresh@example.com")
        token = CONFIRM_LINK.search(mail.outbox[0].body).group("token")
        Dojo_User.objects.create_user(username="email_late", email="Fresh@example.com")
        self.client.force_login(self.reader)
        self.client.get(reverse("confirm_email_change", args=(token,)))
        self.assertEqual(self._email_of(self.reader), "reader@example.com")

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=True)
    def test_a_user_without_a_password_cannot_change_own_email(self):
        sso_user = Dojo_User.objects.create_user(username="email_sso", email="sso@example.com")
        sso_user.set_unusable_password()
        sso_user.save()
        self._post_profile(sso_user, email="fresh@example.com")
        self.assertEqual(self._email_of(sso_user), "sso@example.com")
        self.assertEqual(mail.outbox, [])

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=False)
    def test_superuser_changes_own_email_directly_but_not_to_a_taken_one(self):
        self._post_profile(self.superuser, email="Victim@example.com")
        self.assertEqual(self._email_of(self.superuser), "super@example.com")
        self._post_profile(self.superuser, email="super2@example.com")
        self.assertEqual(self._email_of(self.superuser), "super2@example.com")

    @override_settings(EMAIL_CHANGE_CONFIRMATION_ENABLED=False)
    def test_accounts_that_already_share_an_email_keep_editing_other_fields(self):
        Dojo_User.objects.filter(pk=self.reader.pk).update(email="VICTIM@example.com")
        reader = Dojo_User.objects.get(pk=self.reader.pk)
        self._post_profile(reader, first_name="Still works")
        reader.refresh_from_db()
        self.assertEqual(reader.first_name, "Still works")
        self.assertEqual(reader.email, "VICTIM@example.com")


@override_settings(SECURE_SSL_REDIRECT=False)
class AdminUserFormEmailUniquenessTest(DojoTestCase):

    """Add and edit user forms refuse a new email another account already holds, ignoring case."""

    @classmethod
    def setUpTestData(cls):
        cls.superuser = Dojo_User.objects.create(username="uniq_super", is_superuser=True, is_staff=True)
        cls.holder = Dojo_User.objects.create(username="uniq_holder", email="holder@example.com")
        cls.other = Dojo_User.objects.create(username="uniq_other", email="other@example.com")

    def test_add_user_refuses_a_taken_email(self):
        with impersonate(self.superuser):
            form = AddDojoUserForm({"username": "uniq_new", "email": "HOLDER@example.com", "password": "Not-a-secret-1!xY", "is_active": "on"})
            self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_edit_user_refuses_a_taken_email(self):
        with impersonate(self.superuser):
            form = EditDojoUserForm({"username": "uniq_other", "email": "Holder@Example.com", "is_active": "on"}, instance=self.other)
            self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_edit_user_keeps_an_already_shared_email(self):
        Dojo_User.objects.filter(pk=self.other.pk).update(email="holder@example.com")
        self.other.refresh_from_db()
        with impersonate(self.superuser):
            form = EditDojoUserForm({"username": "uniq_other", "first_name": "x", "email": "holder@example.com", "is_active": "on"}, instance=self.other)
            self.assertTrue(form.is_valid(), form.errors)


@override_settings(SECURE_SSL_REDIRECT=False)
class ApiUserEmailUniquenessTest(DojoTestCase):

    """API v2 and v3 user create and update refuse a new email another account already holds."""

    @classmethod
    def setUpTestData(cls):
        cls.manager = Dojo_User.objects.create(username="api_uniq_manager", is_active=True)
        cls.manager.user_permissions.add(
            *Permission.objects.filter(
                content_type__app_label="auth", codename__in=("view_user", "add_user", "change_user"),
            ),
        )
        cls.holder = Dojo_User.objects.create(username="api_uniq_holder", email="holder@example.com")
        cls.other = Dojo_User.objects.create(username="api_uniq_other", email="other@example.com")

    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(self.manager)

    def test_v2_create_refuses_a_taken_email(self):
        response = self.api.post(
            reverse("user-list"),
            {"username": "api_uniq_new", "email": "HOLDER@example.com", "password": "Not-a-secret-1!xY"},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(Dojo_User.objects.filter(username="api_uniq_new").exists())

    def test_v2_update_refuses_a_taken_email(self):
        for user in (self.other, self.manager):
            response = self.api.patch(reverse("user-detail", args=(user.pk,)), {"email": "Holder@example.com"}, format="json")
            self.assertEqual(response.status_code, 400, response.content)
            persisted = Dojo_User.objects.get(pk=user.pk).email
            self.assertNotEqual(persisted.lower(), "holder@example.com", msg=f"persisted={persisted}")

    def test_v2_update_of_other_fields_keeps_a_shared_email(self):
        Dojo_User.objects.filter(pk=self.other.pk).update(email="HOLDER@example.com")
        response = self.api.patch(
            reverse("user-detail", args=(self.other.pk,)),
            {"first_name": "Kept", "email": "HOLDER@example.com"},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
