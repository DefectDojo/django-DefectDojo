from django.contrib.auth.models import Permission
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import User
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class UserIdentityFieldAuthzTest(APITestCase):

    """
    A non-superuser holding the user-management configuration permissions must
    not be able to change the identity fields (email/username) of another
    account. Changing another user's email would enable account takeover via
    the email-based password-reset flow.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        # Non-superuser delegate with only the user-management config permissions.
        self.delegate = User.objects.create_user(
            username="identity_authz_delegate",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        self.delegate.user_permissions.add(
            Permission.objects.get(codename="view_user", content_type__app_label="auth"),
            Permission.objects.get(codename="change_user", content_type__app_label="auth"),
        )
        self.target = User.objects.create_user(
            username="identity_authz_target",
            email="target@example.com",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        token = Token.objects.create(user=self.delegate)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def _user_url(self, user_id):
        return f"{reverse('user-list')}{user_id}/"

    def test_delegate_cannot_change_another_users_email(self):
        r = self.client.patch(self._user_url(self.target.id), {"email": "attacker@evil.example"})
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.target.refresh_from_db()
        self.assertEqual(self.target.email, "target@example.com")

    def test_delegate_cannot_change_another_users_username(self):
        r = self.client.patch(self._user_url(self.target.id), {"username": "hijacked"})
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.target.refresh_from_db()
        self.assertEqual(self.target.username, "identity_authz_target")

    def test_delegate_can_change_own_email(self):
        r = self.client.patch(self._user_url(self.delegate.id), {"email": "mynew@example.com"})
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.delegate.refresh_from_db()
        self.assertEqual(self.delegate.email, "mynew@example.com")

    @staticmethod
    def _perm_id(codename):
        return Permission.objects.get(codename=codename, content_type__app_label="auth").id

    def test_delegate_cannot_self_grant_configuration_permissions(self):
        # The delegate holds view_user + change_user; it must not be able to add
        # further configuration permissions (here: add_user) to itself.
        payload = {"configuration_permissions": [
            self._perm_id("view_user"), self._perm_id("change_user"), self._perm_id("add_user"),
        ]}
        r = self.client.patch(self._user_url(self.delegate.id), payload, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertFalse(self.delegate.user_permissions.filter(codename="add_user").exists())

    def test_delegate_cannot_grant_configuration_permissions_to_another_user(self):
        payload = {"configuration_permissions": [self._perm_id("add_user")]}
        r = self.client.patch(self._user_url(self.target.id), payload, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertFalse(self.target.user_permissions.filter(codename="add_user").exists())

    def test_superuser_can_grant_configuration_permissions(self):
        admin = User.objects.get(username="admin")
        admin_token, _ = Token.objects.get_or_create(user=admin)
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION="Token " + admin_token.key)
        payload = {"configuration_permissions": [self._perm_id("add_user")]}
        r = admin_client.patch(self._user_url(self.target.id), payload, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertTrue(self.target.user_permissions.filter(codename="add_user").exists())
