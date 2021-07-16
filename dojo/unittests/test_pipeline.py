from django.test import TestCase
from unittest.mock import patch
from dojo.models import Dojo_User, System_Settings, Dojo_Group, Role
from dojo.authorization.roles_permissions import Roles
from dojo.pipeline import modify_permissions


class TestPipeline(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User()
        cls.user.id = 1

        cls.group = Dojo_Group()
        cls.group.id = 1

        cls.system_settings = System_Settings()
        cls.system_settings.staff_user_email_pattern = '.*@example.com'

    @patch('dojo.models.System_Settings.objects')
    def test_modify_permissions_user_is_staff(self, mock):
        mock.get.return_value = self.system_settings

        self.user.email = 'user.user@example.com'
        self.user.is_staff = False
        modify_permissions(backend=None, uid=None, user=self.user, is_new=True)

        self.assertTrue(self.user.is_staff)

    @patch('dojo.models.System_Settings.objects')
    def test_modify_permissions_user_not_staff(self, mock):
        mock.get.return_value = self.system_settings

        self.user.email = 'user.user@partner.example.com'
        self.user.is_staff = False
        modify_permissions(backend=None, uid=None, user=self.user, is_new=True)

        self.assertFalse(self.user.is_staff)
