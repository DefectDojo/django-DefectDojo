from django.conf import settings
from django.test import TestCase
from unittest.mock import patch
from dojo.models import Product_Type
from dojo.authorization.roles_permissions import Permissions
from dojo.templatetags.authorization_tags import has_object_permission


class TestAuthorizationTags(TestCase):

    def setUp(self):
        self.product_type = Product_Type()
        self.setting_FEATURE_NEW_AUTHORIZATION = settings.FEATURE_NEW_AUTHORIZATION
        self.setting_AUTHORIZATION_STAFF_OVERRIDE = settings.AUTHORIZATION_STAFF_OVERRIDE

    def tearDown(self):
        settings.FEATURE_NEW_AUTHORIZATION = self.setting_FEATURE_NEW_AUTHORIZATION
        settings.AUTHORIZATION_STAFF_OVERRIDE = self.setting_AUTHORIZATION_STAFF_OVERRIDE

    def test_has_object_permission_legacy(self):
        settings.FEATURE_NEW_AUTHORIZATION = False

        result = has_object_permission(self.product_type, Permissions.Product_Type_View)

        self.assertFalse(result)

    @patch('dojo.templatetags.authorization_tags.user_has_permission')
    def test_has_object_permission_no_permission(self, mock_has_permission):
        mock_has_permission.return_value = False

        settings.FEATURE_NEW_AUTHORIZATION = True

        result = has_object_permission(self.product_type, 'Product_Type_View')

        self.assertFalse(result)
        mock_has_permission.assert_called_with(None, self.product_type, Permissions.Product_Type_View)

    @patch('dojo.templatetags.authorization_tags.user_has_permission')
    def test_has_object_permission_has_permission(self, mock_has_permission):
        mock_has_permission.return_value = True

        settings.FEATURE_NEW_AUTHORIZATION = True

        result = has_object_permission(self.product_type, 'Product_Type_View')

        self.assertTrue(result)
        mock_has_permission.assert_called_with(None, self.product_type, Permissions.Product_Type_View)

    def test_has_object_permission_wrong_permission(self):
        settings.FEATURE_NEW_AUTHORIZATION = True

        with self.assertRaises(KeyError):
            result = has_object_permission(self.product_type, 'Test')
