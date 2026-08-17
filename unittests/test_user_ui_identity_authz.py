from crum import set_current_user
from django.contrib.auth.models import Permission
from django.urls import reverse

from dojo.models import Dojo_User
from dojo.user.ui.forms import EditDojoUserForm
from unittests.dojo_test_case import DojoTestCase


class UserUIIdentityFieldAuthzTest(DojoTestCase):

    """
    UI twin of test_apiv2_user_identity_authz. A non-superuser holding the
    user-management configuration permission must not be able to change the
    identity fields (username/email) of another account through the classic
    edit_user view / EditDojoUserForm; changing a victim's email enables
    account takeover via the password-reset flow.
    """

    @classmethod
    def setUpTestData(cls):
        cls.delegate = Dojo_User.objects.create(username="ui_identity_delegate", is_active=True)
        cls.delegate.user_permissions.add(
            Permission.objects.get(codename="view_user", content_type__app_label="auth"),
            Permission.objects.get(codename="change_user", content_type__app_label="auth"),
        )
        cls.superuser = Dojo_User.objects.create(username="ui_identity_super", is_active=True, is_superuser=True, is_staff=True)
        cls.target = Dojo_User.objects.create(username="ui_identity_target", email="target@example.com", is_active=True)

    def tearDown(self):
        set_current_user(None)
        super().tearDown()

    def _edit_data(self, **overrides):
        data = {"username": self.target.username, "email": self.target.email, "is_active": "on"}
        data.update(overrides)
        return data

    # form-level guard

    def test_form_blocks_delegate_changing_another_email(self):
        set_current_user(self.delegate)
        form = EditDojoUserForm(self._edit_data(email="attacker@evil.example"), instance=self.target)
        self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_form_blocks_delegate_changing_another_username(self):
        set_current_user(self.delegate)
        form = EditDojoUserForm(self._edit_data(username="hijacked"), instance=self.target)
        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)

    def test_form_allows_superuser_changing_another_email(self):
        set_current_user(self.superuser)
        form = EditDojoUserForm(self._edit_data(email="newby-admin@example.com"), instance=self.target)
        self.assertTrue(form.is_valid(), form.errors)

    def test_form_allows_delegate_changing_own_email(self):
        set_current_user(self.delegate)
        data = {"username": self.delegate.username, "email": "mynew@example.com", "is_active": "on"}
        form = EditDojoUserForm(data, instance=self.delegate)
        self.assertTrue(form.is_valid(), form.errors)

    # end-to-end: the reported PoC no longer changes the victim's email

    def test_delegate_post_cannot_change_target_email(self):
        self.client.force_login(self.delegate)
        self.client.post(
            reverse("edit_user", args=(self.target.id,)),
            self._edit_data(email="attacker@evil.example"),
        )
        self.target.refresh_from_db()
        self.assertEqual(self.target.email, "target@example.com")
