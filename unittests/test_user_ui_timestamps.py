from datetime import UTC, datetime
from unittest.mock import patch

from django.contrib.auth.tokens import default_token_generator
from django.test import TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from dojo.authorization.models import Global_Role, Role
from dojo.models import Dojo_User, User, UserContactInfo
from dojo.user.authentication import reset_token_for_user
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class TestUserUITimestamps(TestCase):
    fixtures = ["dojo_testdata.json"]

    @patch("dojo.user.authentication.create_notification")
    def test_view_user_contains_timestamps(self, mock_create_notification):
        fixed = datetime(2025, 12, 12, 12, 0, 0, tzinfo=UTC)
        admin = Dojo_User.objects.get(username="admin")

        # Create a target user and rotate their token at a fixed time.
        target = User.objects.create(username="ui-ts-target", email="ui-ts-target@dojo.com")
        with patch("dojo.user.authentication.timezone.now", return_value=fixed):
            reset_token_for_user(acting_user=admin, target_user=target)

        # Ensure the UI can render and the timestamps match what we wrote.
        self.client.force_login(admin)
        resp = self.client.get(f"/user/{target.id}")
        self.assertEqual(resp.status_code, 200)
        viewed_user = resp.context["user"]
        self.assertEqual(viewed_user.usercontactinfo.token_last_reset, fixed)

        # Now set password_last_reset to a fixed timestamp and assert it is exposed too.
        uci, _ = UserContactInfo.objects.get_or_create(user=target)
        uci.password_last_reset = fixed
        uci.save(update_fields=["password_last_reset"])
        resp = self.client.get(f"/user/{target.id}")
        viewed_user = resp.context["user"]
        self.assertEqual(viewed_user.usercontactinfo.password_last_reset, fixed)

    def test_change_password_stamps_password_last_reset(self):
        fixed = datetime(2025, 12, 12, 12, 0, 0, tzinfo=UTC)
        user = User.objects.create(username="pwd-change-user", email="pwd-change-user@dojo.com", is_active=True)
        user.set_password("OldPass123!@#")
        user.save()

        self.client.force_login(user)
        with patch("dojo.user.ui.views.now", return_value=fixed):
            resp = self.client.post(
                reverse("change_password"),
                data={
                    "current_password": "OldPass123!@#",
                    "new_password": "NewPass123!@#",
                    "confirm_password": "NewPass123!@#",
                },
            )
        # Successful change redirects to profile
        self.assertEqual(resp.status_code, 302)

        uci = UserContactInfo.objects.get(user=user)
        self.assertEqual(uci.password_last_reset, fixed)

    def test_password_reset_confirm_stamps_password_last_reset(self):
        fixed = datetime(2025, 12, 12, 12, 0, 0, tzinfo=UTC)
        user = User.objects.create(username="pwd-reset-user", email="pwd-reset-user@dojo.com", is_active=True)
        user.set_password("OldPass123!@#")
        user.save()

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        url = reverse("password_reset_confirm", kwargs={"uidb64": uidb64, "token": token})

        with patch("dojo.user.ui.views.now", return_value=fixed):
            # Django's PasswordResetConfirmView typically requires a GET to the tokenized URL,
            # which sets a session token and redirects to the "set-password" URL.
            resp_get = self.client.get(url)
            self.assertEqual(resp_get.status_code, 302)
            set_password_url = resp_get["Location"]

            resp = self.client.post(
                set_password_url,
                data={
                    "new_password1": "NewPass123!@#",
                    "new_password2": "NewPass123!@#",
                },
            )

        # PasswordResetConfirmView redirects to reset done on success
        self.assertEqual(resp.status_code, 302)
        uci = UserContactInfo.objects.get(user=user)
        self.assertEqual(uci.password_last_reset, fixed)

    def test_user_list_page_renders(self):
        # Regression: /user previously called select_related("global_role"),
        # but Global_Role.user uses related_name="+" under legacy
        # authorization, so Dojo_User has no `global_role` reverse accessor.
        # The select_related raised FieldError and 500'd the page.
        admin = Dojo_User.objects.get(username="admin")
        self.client.force_login(admin)
        resp = self.client.get(reverse("users"))
        self.assertEqual(resp.status_code, 200)

    def test_profile_save_does_not_duplicate_global_role(self):
        # Regression: /profile POST previously did
        #   global_role = user.global_role if hasattr(user, "global_role") else None
        # Under legacy authorization Global_Role.user uses related_name="+"
        # so the hasattr always returned False, the form bound to a fresh
        # Global_Role with no PK, and global_role.save() INSERTed a second
        # row that violated the unique(user_id) constraint and 500'd. The
        # forward-FK lookup must find the existing row and UPDATE it.
        admin = Dojo_User.objects.get(username="admin")
        # Seed an existing Global_Role row for this user (mirrors a Pro
        # snapshot or a stale legacy backfill).
        owner_role = Role.objects.filter(name="Owner").first()
        Global_Role.objects.update_or_create(user=admin, defaults={"role": owner_role})

        self.client.force_login(admin)
        resp = self.client.post(reverse("view_profile"), data={
            "username": admin.username,
            "first_name": admin.first_name,
            "last_name": admin.last_name,
            "email": admin.email,
            "role": owner_role.id if owner_role else "",
        })
        # Must not 500. Either the form bounces back (200) or saves (302).
        self.assertIn(resp.status_code, (200, 302))
        # And there must still be exactly one Global_Role row for admin.
        self.assertEqual(Global_Role.objects.filter(user=admin).count(), 1)
