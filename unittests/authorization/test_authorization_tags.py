from ..dojo_test_case import DojoTestCase
from unittest.mock import patch
from django.contrib.auth.models import Permission, Group
from dojo.models import Product_Type, Dojo_User
from dojo.authorization.roles_permissions import Permissions
from dojo.templatetags.authorization_tags import has_object_permission, has_configuration_permission, \
    user_has_configuration_permission_without_group, group_has_configuration_permission


class TestAuthorizationTags(DojoTestCase):

    def setUp(self):
        self.product_type = Product_Type()

        self.user = Dojo_User()
        self.group = Group()

        self.permission_a = Permission()
        self.permission_a.codename = 'a'
        self.permission_b = Permission()
        self.permission_b.codename = 'b'
        self.permission_c = Permission()
        self.permission_c.codename = 'c'

    @patch('dojo.templatetags.authorization_tags.user_has_permission')
    def test_has_object_permission_no_permission(self, mock_has_permission):
        mock_has_permission.return_value = False

        result = has_object_permission(self.product_type, 'Product_Type_View')

        self.assertFalse(result)
        mock_has_permission.assert_called_with(None, self.product_type, Permissions.Product_Type_View)

    @patch('dojo.templatetags.authorization_tags.user_has_permission')
    @patch('crum.get_current_user')
    def test_has_object_permission_has_permission(self, mock_current_user, mock_has_permission):
        mock_has_permission.return_value = True
        mock_current_user.return_value = self.user

        result = has_object_permission(self.product_type, 'Product_Type_View')

        self.assertTrue(result)
        mock_has_permission.assert_called_with(self.user, self.product_type, Permissions.Product_Type_View)
        mock_current_user.assert_called_once()

    def test_has_object_permission_wrong_permission(self):

        with self.assertRaises(KeyError):
            result = has_object_permission(self.product_type, 'Test')

    @patch('dojo.templatetags.authorization_tags.configuration_permission')
    @patch('crum.get_current_user')
    def test_has_configuration_permission(self, mock_current_user, mock_configuration_permission):
        mock_configuration_permission.return_value = True
        mock_current_user.return_value = self.user

        result = has_configuration_permission('test', 'testLegacy')

        self.assertTrue(result)
        mock_configuration_permission.assert_called_with(self.user, 'test', 'testLegacy')
        mock_current_user.assert_called_once()

    @patch('django.contrib.auth.models.User.user_permissions')
    def test_user_has_configuration_permission_without_group_not_found(self, mock):
        mock.all.return_value = [self.permission_a, self.permission_b, self.permission_c]

        result = user_has_configuration_permission_without_group(self.user, 'test')

        self.assertFalse(result)
        mock.all.assert_called_once()

    @patch('django.contrib.auth.models.User.user_permissions')
    def test_user_has_configuration_permission_without_group_found(self, mock):
        mock.all.return_value = [self.permission_a, self.permission_b, self.permission_c]

        result = user_has_configuration_permission_without_group(self.user, 'b')

        self.assertTrue(result)
        mock.all.assert_called_once()

    @patch('django.contrib.auth.models.Group.permissions')
    def test_group_has_configuration_permission_not_found(self, mock):
        mock.all.return_value = [self.permission_a, self.permission_b, self.permission_c]

        result = group_has_configuration_permission(self.group, 'test')

        self.assertFalse(result)
        mock.all.assert_called_once()

    @patch('django.contrib.auth.models.Group.permissions')
    def test_group_has_configuration_permission(self, mock):
        mock.all.return_value = [self.permission_a, self.permission_b, self.permission_c]

        result = group_has_configuration_permission(self.group, 'b')

        self.assertTrue(result)
        mock.all.assert_called_once()
