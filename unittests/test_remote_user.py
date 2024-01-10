from .dojo_test_case import DojoTestCase
from django.test import Client, override_settings
from dojo.models import User, Dojo_Group, Dojo_Group_Member
from netaddr import IPSet

class TestRemoteUser(DojoTestCase):

    client = Client()

    def setUp(self):
        self.user, _ = User.objects.get_or_create(
            username='test_remote_user',
            first_name='original_first',
            last_name='original_last',
            email='original@mail.com',
        )
        self.group1, _ = Dojo_Group.objects.get_or_create(name="group1")
        self.group2, _ = Dojo_Group.objects.get_or_create(name="group2")

    @override_settings(AUTH_REMOTEUSER_ENABLED=False)
    def test_disabled(self):
        resp = self.client.get(f'/user/{self.user.pk}')
        self.assertEqual(resp.status_code, 302)

    @override_settings(AUTH_REMOTEUSER_ENABLED=True)
    def test_basic(self):
        headers = {
            "REMOTE_USER": "test_remote_user"
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers)
        self.assertEqual(resp.status_code, 200)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_FIRSTNAME_HEADER="REMOTE_FIRSTNAME",
        AUTH_REMOTEUSER_LASTNAME_HEADER="REMOTE_LASTNAME",
        AUTH_REMOTEUSER_EMAIL_HEADER="REMOTE_EMAIL",
    )
    def test_update_user(self):
        headers = {
            "REMOTE_USER": "test_remote_user",
            "REMOTE_FIRSTNAME": "new_first",
            "REMOTE_LASTNAME": "new_last",
            "REMOTE_EMAIL": "new@mail.com",
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        updated_user = User.objects.get(pk=self.user.pk)
        self.assertEqual(updated_user.first_name, "new_first")
        self.assertEqual(updated_user.last_name, "new_last")
        self.assertEqual(updated_user.email, "new@mail.com")

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_GROUPS_HEADER="REMOTE_GROUPS",
        AUTH_REMOTEUSER_GROUPS_CLEANUP=True,
    )
    def test_update_groups_cleanup(self):
        headers = {
            "REMOTE_USER": "test_remote_user",
            "REMOTE_GROUPS": self.group1.name,
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        dgms = Dojo_Group_Member.objects.filter(user=self.user)
        self.assertEqual(dgms.count(), 1)
        self.assertEqual(dgms.first().name, self.group1.name)

        headers = {
            "REMOTE_USER": "test_remote_user",
            "REMOTE_GROUPS": self.group2.name,
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        dgms = Dojo_Group_Member.objects.filter(user=self.user)
        self.assertEqual(dgms.count(), 1)
        self.assertEqual(dgms.first().name, self.group2.name)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_GROUPS_HEADER="REMOTE_GROUPS",
        AUTH_REMOTEUSER_GROUPS_CLEANUP=False,
    )
    def test_update_groups_nocleanup(self):
        headers = {
            "REMOTE_USER": "test_remote_user",
            "REMOTE_GROUPS": self.group1.name,
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers)
        self.assertEqual(resp.status_code, 200)

        headers = {
            "REMOTE_USER": "test_remote_user",
            "REMOTE_GROUPS": self.group2.name,
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        dgms = Dojo_Group_Member.objects.filter(user=self.user)
        self.assertEqual(dgms.count(), 2)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_TRUSTED_PROXY=IPSet(['192.168.0.0/24', '192.168.2.0/24']),
    )
    def test_trusted_proxy(self):
        headers = {
            "REMOTE_USER": "test_remote_user"
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers, REMOTE_ADDR='192.168.0.42')
        self.assertEqual(resp.status_code, 200)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_TRUSTED_PROXY=IPSet(['192.168.0.0/24', '192.168.2.0/24']),
    )
    def test_untrusted_proxy(self):
        headers = {
            "REMOTE_USER": "test_remote_user"
        }
        resp = self.client.get(f'/user/{self.user.pk}', headers=headers, REMOTE_ADDR='192.168.1.42')
        self.assertEqual(resp.status_code, 401)
