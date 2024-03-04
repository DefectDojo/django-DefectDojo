from django.test import Client, override_settings
from netaddr import IPSet
from dojo.models import User, Dojo_Group, Dojo_Group_Member
from .dojo_test_case import DojoTestCase


class TestRemoteUser(DojoTestCase):

    client1 = Client()
    client2 = Client()

    def setUp(self):
        self.user, _ = User.objects.get_or_create(
            username='test_remote_user',
            first_name='original_first',
            last_name='original_last',
            email='original@mail.com',
        )
        self.group1, _ = Dojo_Group.objects.get_or_create(name="group1", social_provider=Dojo_Group.REMOTE)
        self.group2, _ = Dojo_Group.objects.get_or_create(name="group2", social_provider=Dojo_Group.REMOTE)

    @override_settings(AUTH_REMOTEUSER_ENABLED=False)
    def test_disabled(self):
        resp = self.client1.get('/profile')
        self.assertEqual(resp.status_code, 302)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_USERNAME_HEADER="HTTP_REMOTE_USER",
    )
    def test_basic(self):
        resp = self.client1.get('/profile',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                # headers={
                                #     "Remote-User": self.user.username
                                # }
                                )
        self.assertEqual(resp.status_code, 200)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_USERNAME_HEADER="HTTP_REMOTE_USER",
        AUTH_REMOTEUSER_FIRSTNAME_HEADER="HTTP_REMOTE_FIRSTNAME",
        AUTH_REMOTEUSER_LASTNAME_HEADER="HTTP_REMOTE_LASTNAME",
        AUTH_REMOTEUSER_EMAIL_HEADER="HTTP_REMOTE_EMAIL",
    )
    def test_update_user(self):
        resp = self.client1.get('/profile',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                HTTP_REMOTE_FIRSTNAME="new_first",
                                HTTP_REMOTE_LASTNAME="new_last",
                                HTTP_REMOTE_EMAIL="new@mail.com",
                                # headers = {
                                #     "Remote-User": self.user.username,
                                #     "Remote-Firstname": "new_first",
                                #     "Remote-Lastname": "new_last",
                                #     "Remote-Email": "new@mail.com",
                                # }
                                )
        self.assertEqual(resp.status_code, 200)
        updated_user = User.objects.get(pk=self.user.pk)
        self.assertEqual(updated_user.first_name, "new_first")
        self.assertEqual(updated_user.last_name, "new_last")
        self.assertEqual(updated_user.email, "new@mail.com")

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_USERNAME_HEADER="HTTP_REMOTE_USER",
        AUTH_REMOTEUSER_GROUPS_HEADER="HTTP_REMOTE_GROUPS",
        AUTH_REMOTEUSER_GROUPS_CLEANUP=True,
    )
    def test_update_groups_cleanup(self):
        resp = self.client1.get('/profile',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                HTTP_REMOTE_GROUPS=self.group1.name,
                                # headers = {
                                #     "Remote-User": self.user.username,
                                #     "Remote-Groups": self.group1.name,
                                # }
                                )
        self.assertEqual(resp.status_code, 200)
        dgms = Dojo_Group_Member.objects.filter(user=self.user)
        self.assertEqual(dgms.count(), 1)
        self.assertEqual(dgms.first().group.name, self.group1.name)

        resp = self.client2.get('/profile',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                HTTP_REMOTE_GROUPS=self.group2.name,
                                # headers = {
                                #     "Remote-User": self.user.username,
                                #     "Remote-Groups": self.group2.name,
                                # }
                                )
        self.assertEqual(resp.status_code, 200)
        dgms = Dojo_Group_Member.objects.all().filter(user=self.user)
        self.assertEqual(dgms.count(), 1)
        self.assertEqual(dgms.first().group.name, self.group2.name)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_USERNAME_HEADER="HTTP_REMOTE_USER",
        AUTH_REMOTEUSER_GROUPS_HEADER="HTTP_REMOTE_GROUPS",
        AUTH_REMOTEUSER_GROUPS_CLEANUP=True,
    )
    def test_update_multiple_groups_cleanup(self):
        resp = self.client1.get('/profile',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                HTTP_REMOTE_GROUPS=f"{self.group1.name},{self.group2.name}",
                                # headers = {
                                #     "Remote-User": self.user.username,
                                #     "Remote-Groups": f"{self.group1.name},{self.group2.name}",
                                # }
                                )
        self.assertEqual(resp.status_code, 200)
        dgms = Dojo_Group_Member.objects.filter(user=self.user)
        self.assertEqual(dgms.count(), 2)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_USERNAME_HEADER="HTTP_REMOTE_USER",
        AUTH_REMOTEUSER_GROUPS_HEADER="HTTP_REMOTE_GROUPS",
        AUTH_REMOTEUSER_GROUPS_CLEANUP=False,
    )
    def test_update_groups_no_cleanup(self):
        resp = self.client1.get('/profile',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                HTTP_REMOTE_GROUPS=self.group1.name,
                                # headers = {
                                #     "Remote-User": self.user.username,
                                #     "Remote-Groups": self.group1.name,
                                # }
                                )
        self.assertEqual(resp.status_code, 200)

        resp = self.client2.get('/profile',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                HTTP_REMOTE_GROUPS=self.group2.name,
                                # headers = {
                                #     "Remote-User": self.user.username,
                                #     "Remote-Groups": self.group2.name,
                                # }
                                )
        self.assertEqual(resp.status_code, 200)
        dgms = Dojo_Group_Member.objects.filter(user=self.user)
        self.assertEqual(dgms.count(), 2)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_USERNAME_HEADER="HTTP_REMOTE_USER",
        AUTH_REMOTEUSER_TRUSTED_PROXY=IPSet(['192.168.0.0/24', '192.168.2.0/24']),
    )
    def test_trusted_proxy(self):
        resp = self.client1.get('/profile',
                                REMOTE_ADDR='192.168.0.42',
                                # TODO - This can be replaced by following lines in the future
                                # Using of "headers" is supported since Django 4.2
                                HTTP_REMOTE_USER=self.user.username,
                                # headers = {
                                #     "Remote-User": self.user.username,
                                # }
                                )
        self.assertEqual(resp.status_code, 200)

    @override_settings(
        AUTH_REMOTEUSER_ENABLED=True,
        AUTH_REMOTEUSER_USERNAME_HEADER="HTTP_REMOTE_USER",
        AUTH_REMOTEUSER_TRUSTED_PROXY=IPSet(['192.168.0.0/24', '192.168.2.0/24']),
    )
    def test_untrusted_proxy(self):
        with self.assertLogs('dojo.remote_user', level='DEBUG') as cm:
            resp = self.client1.get('/profile',
                                    REMOTE_ADDR='192.168.1.42',
                                    # TODO - This can be replaced by following lines in the future
                                    # Using of "headers" is supported since Django 4.2
                                    HTTP_REMOTE_USER=self.user.username,
                                    # headers = {
                                    #     "Remote-User": self.user.username,
                                    # }
                                    )
        self.assertEqual(resp.status_code, 302)
        self.assertIn('Requested came from untrusted proxy', cm.output[0])
