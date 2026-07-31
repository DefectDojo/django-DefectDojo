from django.contrib.auth.models import Permission
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import User
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class UserDeleteAuthzTest(APITestCase):

    """
    A non-superuser holding the user-management configuration permissions must
    not be able to delete a superuser or a staff account. The write-path guards
    in UserSerializer.validate() do not run on DELETE, so the viewset carries
    the same privilege floor.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.delegate = User.objects.create_user(
            username="delete_authz_delegate",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        self.delegate.user_permissions.add(
            Permission.objects.get(codename="view_user", content_type__app_label="auth"),
            Permission.objects.get(codename="change_user", content_type__app_label="auth"),
            Permission.objects.get(codename="delete_user", content_type__app_label="auth"),
        )
        self.superuser_target = User.objects.create_user(
            username="delete_authz_superuser",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_superuser=True,
        )
        self.staff_target = User.objects.create_user(
            username="delete_authz_staff",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_staff=True,
        )
        self.regular_target = User.objects.create_user(
            username="delete_authz_regular",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        token = Token.objects.create(user=self.delegate)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def _user_url(self, user_id):
        return f"{reverse('user-list')}{user_id}/"

    def _superuser_client(self):
        admin = User.objects.get(username="admin")
        admin_token, _ = Token.objects.get_or_create(user=admin)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + admin_token.key)
        return client

    def test_delegate_cannot_delete_superuser(self):
        r = self.client.delete(self._user_url(self.superuser_target.id))
        self.assertEqual(r.status_code, 403, r.content[:1000])
        self.assertTrue(User.objects.filter(pk=self.superuser_target.pk).exists())

    def test_delegate_cannot_delete_staff_user(self):
        r = self.client.delete(self._user_url(self.staff_target.id))
        self.assertEqual(r.status_code, 403, r.content[:1000])
        self.assertTrue(User.objects.filter(pk=self.staff_target.pk).exists())

    def test_delegate_can_delete_regular_user(self):
        r = self.client.delete(self._user_url(self.regular_target.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])
        self.assertFalse(User.objects.filter(pk=self.regular_target.pk).exists())

    def test_delegate_cannot_delete_themselves(self):
        r = self.client.delete(self._user_url(self.delegate.id))
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertTrue(User.objects.filter(pk=self.delegate.pk).exists())

    def test_superuser_can_delete_superuser(self):
        r = self._superuser_client().delete(self._user_url(self.superuser_target.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])
        self.assertFalse(User.objects.filter(pk=self.superuser_target.pk).exists())

    def test_superuser_can_delete_staff_user(self):
        r = self._superuser_client().delete(self._user_url(self.staff_target.id))
        self.assertEqual(r.status_code, 204, r.content[:1000])
        self.assertFalse(User.objects.filter(pk=self.staff_target.pk).exists())
