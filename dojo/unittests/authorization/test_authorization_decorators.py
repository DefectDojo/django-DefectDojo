from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.test import TestCase, RequestFactory
from unittest.mock import patch, Mock
from dojo.models import Product_Type
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions


class TestAuthorizationDecorators(TestCase):

    def setUp(self):
        self.request = RequestFactory().get('/dummy')
        self.user = User()
        self.request.user = self.user
        self.product_type = Product_Type()
        self.decorated_func = user_is_authorized(Product_Type, Permissions.Product_Type_View, 'id', None, 'pk', Mock())
        self.decorated_func_legacy = user_is_authorized(Product_Type, Permissions.Product_Type_View, 'id', 'staff', 'pk', Mock())
        self.setting_FEATURE_NEW_AUTHORIZATION = settings.FEATURE_NEW_AUTHORIZATION
        self.setting_AUTHORIZATION_STAFF_OVERRIDE = settings.AUTHORIZATION_STAFF_OVERRIDE

    def tearDown(self):
        settings.FEATURE_NEW_AUTHORIZATION = self.setting_FEATURE_NEW_AUTHORIZATION
        settings.AUTHORIZATION_STAFF_OVERRIDE = self.setting_AUTHORIZATION_STAFF_OVERRIDE

    @patch('dojo.authorization.authorization_decorators.get_object_or_404', side_effect=Http404())
    def test_object_does_not_exist(self, shortcuts_get_mock):

        with self.assertRaises(Http404):
            self.decorated_func(self.request, 1)

        shortcuts_get_mock.assert_called_once()

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    @patch('dojo.authorization.authorization_decorators.user_has_permission_or_403', side_effect=PermissionDenied())
    def test_new_authorization_permission_denied(self, mock_user_has_permission, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = True
        self.user.is_superuser = False

        with self.assertRaises(PermissionDenied):
            self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()
        mock_user_has_permission.assert_called_with(self.user, self.product_type, Permissions.Product_Type_View)

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    def test_new_authorization_superuser(self, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = True
        self.user.is_superuser = True

        self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    def test_new_authorization_staff_override(self, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = True
        settings.AUTHORIZATION_STAFF_OVERRIDE = True
        self.user.is_staff = True

        self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()

        settings.AUTHORIZATION_STAFF_OVERRIDE = False

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    @patch('dojo.authorization.authorization_decorators.user_has_permission_or_403')
    def test_new_authorization_user_has_permission(self, mock_user_has_permission, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = True
        self.user.is_superuser = False

        self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()
        mock_user_has_permission.assert_called_with(self.user, self.product_type, Permissions.Product_Type_View)

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    def test_legacy_authorization_no_legacy_permission_non_staff(self, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = False
        self.user.is_staff = False

        with self.assertRaises(PermissionDenied):
            self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    def test_legacy_authorization_no_legacy_permission_is_staff(self, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = False
        self.user.is_staff = True

        self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    @patch('dojo.authorization.authorization_decorators.legacy_check')
    def test_legacy_authorization_legacy_permission_permission_denied(self, mock_legacy_check, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = False
        mock_legacy_check.return_value = False

        with self.assertRaises(PermissionDenied):
            self.decorated_func_legacy(self.request, 1)

        mock_shortcuts_get.assert_called_once()
        mock_legacy_check.assert_called_with(self.user, 'staff', self.product_type)

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    @patch('dojo.authorization.authorization_decorators.legacy_check')
    def test_legacy_authorization_legacy_permission_user_has_permission(self, mock_legacy_check, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        settings.FEATURE_NEW_AUTHORIZATION = False
        mock_legacy_check.return_value = True

        self.decorated_func_legacy(self.request, 1)

        mock_shortcuts_get.assert_called_once()
        mock_legacy_check.assert_called_with(self.user, 'staff', self.product_type)
