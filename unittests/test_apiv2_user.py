from django.contrib.auth.models import Permission
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.authorization.models import Global_Role, Role
from dojo.models import User, UserContactInfo
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class UserTest(APITestCase):

    """Test the User APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def test_user_list(self):
        r = self.client.get(reverse("user-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        user_list = r.json()["results"]
        self.assertGreaterEqual(len(user_list), 1, r.content[:1000])
        for user in user_list:
            for item in ["username", "first_name", "last_name", "email"]:
                self.assertIn(item, user, r.content[:1000])
            for item in ["password"]:
                self.assertNotIn(item, user, r.content[:1000])

    def test_user_add(self):
        # user with good password
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-2",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])

        # test password by fetching API key
        r = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-2",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        # user with weak password
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-3",
            "email": "admin@dojo.com",
            "password": "weakPassword",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Password must contain at least 1 digit, 0-9.", r.content.decode("utf-8"))

    def test_user_change_password(self):
        # some user
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-4",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        r = self.client.put("{}{}/".format(reverse("user-list"), user_id), {
            "username": "api-user-4",
            "first_name": "first",
            "email": "admin@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "last_name": "last",
            "email": "admin@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        r = self.client.put("{}{}/".format(reverse("user-list"), user_id), {
            "username": "api-user-4",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Update of password though API is not allowed", r.content.decode("utf-8"))

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "password": "testTEST1234!@#$",
            "email": "admin@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Update of password though API is not allowed", r.content.decode("utf-8"))

    def test_user_deactivate(self):
        # user with good password
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-10",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])

        # user with good password
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-2",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        # deactivate
        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "is_active": False,
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        # check is_active field
        r = self.client.get("{}{}/".format(reverse("user-list"), user_id))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertEqual(r.json()["is_active"], False, r.content[:1000])

        # API key retrieval should fail for inactive user
        r = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-2",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])

    def test_user_reset_api_token_as_superuser(self):
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-reset-1",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        target_user = User.objects.get(id=user_id)
        # Tokens aren't created automatically for new users; ensure one exists.
        old_token = Token.objects.get_or_create(user=target_user)[0].key

        url = "{}{}/reset_api_token/".format(reverse("user-list"), user_id)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 204, r.content[:1000])

        new_token = Token.objects.get(user=target_user).key
        self.assertNotEqual(old_token, new_token)

        uci = UserContactInfo.objects.get(user=target_user)
        self.assertIsNotNone(uci.token_last_reset)
        self.assertLess(abs((timezone.now() - uci.token_last_reset).total_seconds()), 30)

    def test_user_reset_api_token_denies_self(self):
        admin_user = User.objects.get(username="admin")
        admin_token_before = Token.objects.get(user=admin_user).key

        url = "{}{}/reset_api_token/".format(reverse("user-list"), admin_user.id)
        r = self.client.post(url)
        self.assertIn(r.status_code, {400, 403}, r.content[:1000])

        admin_token_after = Token.objects.get(user=admin_user).key
        self.assertEqual(admin_token_before, admin_token_after)

    def test_user_reset_api_token_denies_non_privileged(self):
        # Create a target
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-reset-target",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        # Create a non-privileged user and authenticate as them
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-nonpriv",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-nonpriv",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        nonpriv_token = token_resp.json()["token"]

        nonpriv_client = APIClient()
        nonpriv_client.credentials(HTTP_AUTHORIZATION="Token " + nonpriv_token)

        url = "{}{}/reset_api_token/".format(reverse("user-list"), target_id)
        r = nonpriv_client.post(url)
        self.assertEqual(r.status_code, 403, r.content[:1000])

    def test_non_superuser_cannot_set_is_staff_via_api(self):
        """
        A delegated user-manager (auth.change_user) must not be able to
        flip is_staff on themselves or anyone else — is_staff is a
        superuser-only flag under the legacy OS auth model, and granting
        it via API would let a non-superuser pivot into Django admin /
        full RBAC bypass.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-mgr",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        mgr = User.objects.get(username="api-user-mgr")
        mgr.user_permissions.add(
            Permission.objects.get(codename="change_user"),
            Permission.objects.get(codename="add_user"),
        )

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-mgr",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        mgr_client = APIClient()
        mgr_client.credentials(HTTP_AUTHORIZATION="Token " + token_resp.json()["token"])

        # Self-escalation: setting is_staff on own account must be rejected.
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), mgr.id), {
            "is_staff": True,
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn(
            "Only superusers are allowed to add or edit staff users.",
            r.content.decode("utf-8"),
        )
        mgr.refresh_from_db()
        self.assertFalse(mgr.is_staff)

        # Target-escalation: setting is_staff on another user must be rejected.
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-target",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        r = mgr_client.patch("{}{}/".format(reverse("user-list"), target_id), {
            "is_staff": True,
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        target = User.objects.get(id=target_id)
        self.assertFalse(target.is_staff)

        # Create-time escalation must also be rejected.
        r = mgr_client.post(reverse("user-list"), {
            "username": "api-user-staff-on-create",
            "email": "admin@dojo.com",
            "password": password,
            "is_staff": True,
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertFalse(User.objects.filter(username="api-user-staff-on-create").exists())

    def test_non_superuser_can_patch_self_without_touching_is_staff(self):
        """
        Negative control for the is_staff guard: a delegated user-manager
        can still PATCH non-privileged fields on their own account; the
        new check only fires when is_staff actually changes.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-mgr2",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        mgr = User.objects.get(username="api-user-mgr2")
        mgr.user_permissions.add(Permission.objects.get(codename="change_user"))

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-mgr2",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        mgr_client = APIClient()
        mgr_client.credentials(HTTP_AUTHORIZATION="Token " + token_resp.json()["token"])

        r = mgr_client.patch("{}{}/".format(reverse("user-list"), mgr.id), {
            "first_name": "Renamed",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

    def test_superuser_can_set_is_staff_via_api(self):
        """Positive control: a superuser is still allowed to toggle is_staff."""
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-promotable",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "is_staff": True,
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertTrue(User.objects.get(id=user_id).is_staff)

    def test_non_superuser_cannot_grant_configuration_permissions_via_api(self):
        """
        Only superusers may assign configuration permissions. A non-superuser,
        even one holding the delegated change_user permission, must not be able
        to grant configuration permissions to their own account or to another
        user, whether on update or at create time. Configuration permissions
        are privilege-bearing (managing users, groups, tool configurations, and
        so on), so assigning them is a superuser-only action.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-cfgperm-mgr",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        mgr = User.objects.get(username="api-cfgperm-mgr")
        # Delegated user-manager: may change and create users, nothing more.
        mgr.user_permissions.add(
            Permission.objects.get(codename="change_user"),
            Permission.objects.get(codename="add_user"),
        )
        delete_user = Permission.objects.get(codename="delete_user")
        add_group = Permission.objects.get(codename="add_group")

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-cfgperm-mgr",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        mgr_client = APIClient()
        mgr_client.credentials(HTTP_AUTHORIZATION="Token " + token_resp.json()["token"])

        # Self-escalation: granting themselves additional configuration
        # permissions must be rejected.
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), mgr.id), {
            "configuration_permissions": [delete_user.id, add_group.id],
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn(
            "Only superusers are allowed to change configuration permissions.",
            r.content.decode("utf-8"),
        )
        self.assertFalse(User.objects.get(id=mgr.id).has_perm("auth.delete_user"))
        self.assertFalse(User.objects.get(id=mgr.id).has_perm("auth.add_group"))

        # Target-escalation: granting configuration permissions to another user
        # must be rejected.
        r = self.client.post(reverse("user-list"), {
            "username": "api-cfgperm-target",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        r = mgr_client.patch("{}{}/".format(reverse("user-list"), target_id), {
            "configuration_permissions": [delete_user.id],
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertFalse(User.objects.get(id=target_id).has_perm("auth.delete_user"))

        # Create-time escalation must also be rejected.
        r = mgr_client.post(reverse("user-list"), {
            "username": "api-cfgperm-on-create",
            "email": "admin@dojo.com",
            "password": password,
            "configuration_permissions": [delete_user.id],
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertFalse(User.objects.filter(username="api-cfgperm-on-create").exists())

    def test_non_superuser_can_resend_unchanged_configuration_permissions(self):
        """
        Negative control: the guard only fires when configuration permissions
        actually change, so a delegated user-manager can still PATCH their own
        account (including re-sending the configuration permissions they already
        hold) without being blocked.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-cfgperm-mgr2",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        mgr = User.objects.get(username="api-cfgperm-mgr2")
        change_user = Permission.objects.get(codename="change_user")
        mgr.user_permissions.add(change_user)

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-cfgperm-mgr2",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        mgr_client = APIClient()
        mgr_client.credentials(HTTP_AUTHORIZATION="Token " + token_resp.json()["token"])

        # Re-sending the same configuration permission the user already holds is
        # a no-op and must be allowed.
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), mgr.id), {
            "configuration_permissions": [change_user.id],
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        # Editing an unrelated field is likewise unaffected.
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), mgr.id), {
            "first_name": "Renamed",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

    def test_superuser_can_set_configuration_permissions_via_api(self):
        """Positive control: a superuser may still assign configuration permissions."""
        r = self.client.post(reverse("user-list"), {
            "username": "api-cfgperm-grantable",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]
        delete_user = Permission.objects.get(codename="delete_user")

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "configuration_permissions": [delete_user.id],
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertTrue(User.objects.get(id=user_id).has_perm("auth.delete_user"))

    def test_non_superuser_cannot_change_other_user_email_via_api(self):
        """
        A delegated user-manager (auth.change_user) must not be able to
        change the email address of an account other than their own. This
        mirrors the is_staff and configuration-permission guards: changing
        another user's email is a superuser-only action.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-email-mgr",
            "email": "mgr@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        mgr = User.objects.get(username="api-email-mgr")
        mgr.user_permissions.add(
            Permission.objects.get(codename="change_user"),
            Permission.objects.get(codename="view_user"),
        )

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-email-mgr",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        mgr_client = APIClient()
        mgr_client.credentials(HTTP_AUTHORIZATION="Token " + token_resp.json()["token"])

        r = self.client.post(reverse("user-list"), {
            "username": "api-email-target",
            "email": "target-real@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        # Repointing another account's email must be rejected, and the stored
        # value must be unchanged.
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), target_id), {
            "email": "someone-else@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn(
            "Only superusers are allowed to change the email of another user.",
            r.content.decode("utf-8"),
        )
        self.assertEqual(User.objects.get(id=target_id).email, "target-real@dojo.com")

    def test_non_superuser_can_change_own_email_via_api(self):
        """
        Negative control for the identity-field guard: it only fires when a
        non-superuser changes another account's email or username, so a
        delegated user-manager can still update their own, and re-sending an
        unchanged email on another user stays allowed.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-email-mgr2",
            "email": "mgr2-old@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        mgr = User.objects.get(username="api-email-mgr2")
        mgr.user_permissions.add(Permission.objects.get(codename="change_user"))

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-email-mgr2",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        mgr_client = APIClient()
        mgr_client.credentials(HTTP_AUTHORIZATION="Token " + token_resp.json()["token"])

        # Changing own email is allowed.
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), mgr.id), {
            "email": "mgr2-new@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertEqual(User.objects.get(id=mgr.id).email, "mgr2-new@dojo.com")

        # Changing own username is likewise allowed.
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), mgr.id), {
            "username": "api-email-mgr2-renamed",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertEqual(User.objects.get(id=mgr.id).username, "api-email-mgr2-renamed")

        # Re-sending another user's current email (no change) is a no-op.
        r = self.client.post(reverse("user-list"), {
            "username": "api-email-target2",
            "email": "target2@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]
        r = mgr_client.patch("{}{}/".format(reverse("user-list"), target_id), {
            "email": "target2@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

    def test_superuser_can_change_other_user_email_via_api(self):
        """Positive control: a superuser may still change another user's email."""
        r = self.client.post(reverse("user-list"), {
            "username": "api-email-super-target",
            "email": "before@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "email": "after@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertEqual(User.objects.get(id=user_id).email, "after@dojo.com")

    def test_non_superuser_cannot_change_other_user_username_via_api(self):
        """
        Username is an identity field too: a delegated user-manager
        (auth.change_user) must not be able to change the username of an
        account other than their own.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-uname-mgr",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        mgr = User.objects.get(username="api-uname-mgr")
        mgr.user_permissions.add(Permission.objects.get(codename="change_user"))

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-uname-mgr",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        mgr_client = APIClient()
        mgr_client.credentials(HTTP_AUTHORIZATION="Token " + token_resp.json()["token"])

        r = self.client.post(reverse("user-list"), {
            "username": "api-uname-target",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        r = mgr_client.patch("{}{}/".format(reverse("user-list"), target_id), {
            "username": "api-uname-target-renamed",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn(
            "Only superusers are allowed to change the username of another user.",
            r.content.decode("utf-8"),
        )
        self.assertEqual(User.objects.get(id=target_id).username, "api-uname-target")

    def test_superuser_can_change_other_user_username_via_api(self):
        """Positive control: a superuser may still change another user's username."""
        r = self.client.post(reverse("user-list"), {
            "username": "api-uname-super-target",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "username": "api-uname-super-target-renamed",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertEqual(User.objects.get(id=user_id).username, "api-uname-super-target-renamed")

    def test_user_reset_api_token_denies_global_owner_legacy(self):
        """
        Legacy: Global_Role(role=Owner) is inert. Resetting another
        user's API token requires is_superuser; a global-owner who isn't
        a superuser is treated like any non-privileged user.
        """
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-global-owner",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        global_owner = User.objects.get(username="api-user-global-owner")

        owner_role, _ = Role.objects.get_or_create(name="Owner", defaults={"is_owner": True})
        if not owner_role.is_owner:
            owner_role.is_owner = True
            owner_role.save(update_fields=["is_owner"])
        Global_Role.objects.update_or_create(user=global_owner, defaults={"role": owner_role})

        # Create target
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-reset-2",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        # Authenticate as global owner
        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-global-owner",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        go_token = token_resp.json()["token"]

        go_client = APIClient()
        go_client.credentials(HTTP_AUTHORIZATION="Token " + go_token)

        url = "{}{}/reset_api_token/".format(reverse("user-list"), target_id)
        r = go_client.post(url)
        self.assertEqual(r.status_code, 403, r.content[:1000])
