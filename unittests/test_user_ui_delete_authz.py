from django.contrib.auth.models import Permission
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client
from django.urls import reverse
from rest_framework.authtoken.models import Token
from single_session.models import UserSession

from dojo.models import User
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class UserDeletePageAuthzTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.superuser_target = User.objects.create_user(username="ui_delete_superuser", is_superuser=True)
        self.regular_target = User.objects.create_user(username="ui_delete_regular")
        self.staff = User.objects.create_user(username="ui_delete_staff", is_staff=True)
        self.delegate = User.objects.create_user(username="ui_delete_delegate")
        self.delegate.user_permissions.add(Permission.objects.get(codename="delete_user", content_type__app_label="auth"))

    def _give_credentials(self, user):
        session = SessionStore()
        session.create()
        UserSession.objects.create(session_id=session.session_key, user=user)
        return Token.objects.get_or_create(user=user)[0].key, session.session_key

    def _get(self, acting_user, target):
        client = Client()
        client.force_login(acting_user)
        return client.get(reverse("delete_user", args=(target.id,)))

    def test_staff_and_delegate_cannot_open_superuser_delete_page(self):
        token, session_key = self._give_credentials(self.superuser_target)
        for acting_user in (self.staff, self.delegate):
            with self.subTest(acting_user=acting_user.username):
                r = self._get(acting_user, self.superuser_target)
                self.assertEqual(r.status_code, 302)
                self.assertNotIn(token, r.content.decode())
                self.assertNotIn(session_key, r.content.decode())

    def test_delete_page_hides_token_and_session(self):
        token, session_key = self._give_credentials(self.regular_target)
        r = self._get(self.delegate, self.regular_target)
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertNotIn(token, body)
        self.assertNotIn(session_key, body)
        self.assertIn("APITokenIsHidden", body)
        self.assertIn("SessionIsHidden", body)

    def test_superuser_can_still_delete_superuser(self):
        admin = User.objects.get(username="admin")
        client = Client()
        client.force_login(admin)
        r = client.post(reverse("delete_user", args=(self.superuser_target.id,)), {"id": self.superuser_target.id})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(User.objects.filter(pk=self.superuser_target.pk).exists())
