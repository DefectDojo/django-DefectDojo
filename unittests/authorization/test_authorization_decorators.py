from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import Http404
from ..dojo_test_case import DojoTestCase
from unittest.mock import patch, Mock
from dojo.models import Product_Type
from django.test import RequestFactory
from dojo.authorization.authorization_decorators import user_is_authorized, user_is_configuration_authorized
from dojo.authorization.roles_permissions import Permissions


class TestAuthorizationDecorators(DojoTestCase):

    def setUp(self):
        self.request = RequestFactory().get('/dummy')
        self.user = User()
        self.request.user = self.user
        self.product_type = Product_Type()
        self.decorated_func = user_is_authorized(Product_Type, Permissions.Product_Type_View, 'id', 'pk', Mock())

    @patch('dojo.authorization.authorization_decorators.get_object_or_404', side_effect=Http404())
    def test_object_does_not_exist(self, shortcuts_get_mock):

        with self.assertRaises(Http404):
            self.decorated_func(self.request, 1)

        shortcuts_get_mock.assert_called_once()

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    @patch('dojo.authorization.authorization_decorators.user_has_permission_or_403', side_effect=PermissionDenied())
    def test_authorization_permission_denied(self, mock_user_has_permission, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        self.user.is_superuser = False

        with self.assertRaises(PermissionDenied):
            self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()
        mock_user_has_permission.assert_called_with(self.user, self.product_type, Permissions.Product_Type_View)

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    def test_authorization_superuser(self, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        self.user.is_superuser = True

        self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()

    @patch('dojo.authorization.authorization_decorators.get_object_or_404')
    @patch('dojo.authorization.authorization_decorators.user_has_permission_or_403')
    def test_authorization_user_has_permission(self, mock_user_has_permission, mock_shortcuts_get):
        mock_shortcuts_get.return_value = self.product_type

        self.user.is_superuser = False

        self.decorated_func(self.request, 1)

        mock_shortcuts_get.assert_called_once()
        mock_user_has_permission.assert_called_with(self.user, self.product_type, Permissions.Product_Type_View)


class TestConfigurationAuthorizationDecorators(DojoTestCase):

    def setUp(self):
        self.request = RequestFactory().get('/dummy')
        self.user = User()
        self.request.user = self.user
        self.decorated_func = user_is_configuration_authorized('test', 'testLegacy', Mock())

    @patch('dojo.authorization.authorization_decorators.user_has_configuration_permission')
    def test_authorization_user_has_configuration_permission_ok(self, mock):
        mock.return_value = True

        self.decorated_func(self.request)

        mock.assert_called_with(self.user, 'test', 'testLegacy')

    @patch('dojo.authorization.authorization_decorators.user_has_configuration_permission')
    def test_authorization_user_has_configuration_permission_denied(self, mock):
        mock.return_value = False

        with self.assertRaises(PermissionDenied):
            self.decorated_func(self.request)

        mock.assert_called_with(self.user, 'test', 'testLegacy')
