from django.test.utils import override_settings
from .dojo_test_case import DojoTestCase
from unittest.mock import patch
from dojo.models import Dojo_User, System_Settings
from dojo.pipeline import modify_permissions


class TestPipeline(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User()
        cls.user.id = 1

        cls.system_settings_email = System_Settings()
        cls.system_settings_email.staff_user_email_pattern = '.*@example.com'

    @patch('dojo.models.System_Settings.objects')
    @override_settings(FEATURE_CONFIGURATION_AUTHORIZATION=False)
    def test_modify_permissions_user_is_staff(self, mock):
        mock.get.return_value = self.system_settings_email

        self.user.email = 'user.user@example.com'
        self.user.is_staff = False
        modify_permissions(backend=None, uid=None, user=self.user, is_new=True)

        self.assertTrue(self.user.is_staff)

    @patch('dojo.models.System_Settings.objects')
    @override_settings(FEATURE_CONFIGURATION_AUTHORIZATION=False)
    def test_modify_permissions_user_not_staff(self, mock):
        mock.get.return_value = self.system_settings_email

        self.user.email = 'user.user@partner.example.com'
        self.user.is_staff = False
        modify_permissions(backend=None, uid=None, user=self.user, is_new=True)

        self.assertFalse(self.user.is_staff)
