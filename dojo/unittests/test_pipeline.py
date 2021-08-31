from django.test import TestCase
from unittest.mock import patch, Mock
from dojo.models import Dojo_Group_Member, Dojo_User, System_Settings, Dojo_Group, Role
from dojo.authorization.roles_permissions import Roles
from dojo.pipeline import modify_permissions


class TestPipeline(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User()
        cls.user.id = 1

        cls.group = Dojo_Group()
        cls.group.id = 1

        cls.system_settings_email = System_Settings()
        cls.system_settings_email.staff_user_email_pattern = '.*@example.com'

        cls.role = Role.objects.get(id=Roles.Reader)

        cls.system_settings_group = System_Settings()
        cls.system_settings_group.default_group = cls.group
        cls.system_settings_group.default_group_role = cls.role

    @patch('dojo.models.System_Settings.objects')
    def test_modify_permissions_user_is_staff(self, mock):
        mock.get.return_value = self.system_settings_email

        self.user.email = 'user.user@example.com'
        self.user.is_staff = False
        modify_permissions(backend=None, uid=None, user=self.user, is_new=True)

        self.assertTrue(self.user.is_staff)

    @patch('dojo.models.System_Settings.objects')
    def test_modify_permissions_user_not_staff(self, mock):
        mock.get.return_value = self.system_settings_email

        self.user.email = 'user.user@partner.example.com'
        self.user.is_staff = False
        modify_permissions(backend=None, uid=None, user=self.user, is_new=True)

        self.assertFalse(self.user.is_staff)

    @patch('dojo.models.System_Settings.objects')
    @patch('dojo.pipeline.Dojo_Group_Member')
    def test_modify_permissions_default_group(self, mock_member, mock_settings):
        mock_settings.get.return_value = self.system_settings_group
        save_mock = Mock(return_value=Dojo_Group_Member())
        mock_member.return_value = save_mock
        modify_permissions(backend=None, uid=None, user=self.user, is_new=True)

        mock_member.assert_called_with(group=self.group, user=self.user, role=self.role)
        save_mock.save.assert_called_once()
