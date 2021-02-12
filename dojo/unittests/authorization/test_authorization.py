from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.test import TestCase
from unittest.mock import patch
from dojo.models import Product_Type, Product_Type_Member, Product, Product_Member, Engagement, \
    Test, Finding, Endpoint
from dojo.authorization.authorization import role_has_permission, get_roles_for_permission, \
    user_has_permission_or_403, user_has_permission, \
    RoleDoesNotExistError, PermissionDoesNotExistError, NoAuthorizationImplementedError
from dojo.authorization.roles_permissions import Permissions, Roles


class TestAuthorization(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = User()
        cls.product_type = Product_Type()
        cls.product_type_member = Product_Type_Member()
        cls.product = Product()
        cls.product_member = Product_Member()
        cls.product.prod_type = cls.product_type
        cls.engagement = Engagement()
        cls.engagement.product = cls.product
        cls.test = Test()
        cls.test.engagement = cls.engagement
        cls.finding = Finding()
        cls.finding.test = cls.test
        cls.endpoint = Endpoint()
        cls.endpoint.product = cls.product

        cls.product_type_member_reader = Product_Type_Member()
        cls.product_type_member_reader.user = cls.user
        cls.product_type_member_reader.product_type = cls.product_type
        cls.product_type_member_reader.role = Roles.Reader

        cls.product_type_member_owner = Product_Type_Member()
        cls.product_type_member_owner.user = cls.user
        cls.product_type_member_owner.product_type = cls.product_type
        cls.product_type_member_owner.role = Roles.Owner

        cls.product_member_reader = Product_Member()
        cls.product_member_reader.user = cls.user
        cls.product_member_reader.product = cls.product
        cls.product_member_reader.role = Roles.Reader

        cls.product_member_owner = Product_Member()
        cls.product_member_owner.user = cls.user
        cls.product_member_owner.product = cls.product
        cls.product_member_owner.role = Roles.Owner

    def test_role_has_permission_exception(self):
        with self.assertRaisesMessage(RoleDoesNotExistError,
                'Role 9999 does not exist'):
            role_has_permission(9999, Permissions.Product_Type_Edit)

    def test_role_has_permission_true(self):
        result = role_has_permission(Roles.Maintainer, Permissions.Product_Type_Edit)
        self.assertTrue(result)

    def test_role_has_permission_false(self):
        result = role_has_permission(Roles.Reader, Permissions.Product_Type_Edit)
        self.assertFalse(result)

    def test_get_roles_for_permission_exception(self):
        with self.assertRaisesMessage(PermissionDoesNotExistError,
                'Permission 9999 does not exist'):
            get_roles_for_permission(9999)

    def test_get_roles_for_permission_success(self):
        result = get_roles_for_permission(Permissions.Product_Type_Manage_Members)
        expected = {Roles.Maintainer, Roles.Owner}
        self.assertEqual(result, expected)

    def test_user_has_permission_or_403_exception(self):
        with self.assertRaises(PermissionDenied):
            user_has_permission_or_403(self.user, self.product_type, Permissions.Product_Type_Delete)

    @patch('dojo.models.Product_Type_Member.objects.get')
    def test_user_has_permission_or_403_success(self, mock_get):
        mock_get.return_value = self.product_type_member_owner

        user_has_permission_or_403(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product_type'], self.product_type)

    def test_user_has_permission_exception(self):
        with self.assertRaisesMessage(NoAuthorizationImplementedError,
                'No authorization implemented for class Product_Type_Member and permission 1007'):
            user_has_permission(self.user, self.product_type_member, Permissions.Product_Type_Delete)

    def test_user_has_permission_product_type_no_member(self):
        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_View)
        self.assertFalse(result)

    @patch('dojo.models.Product_Type_Member.objects.get')
    def test_user_has_permission_product_type_no_permissions(self, mock_get):
        mock_get.return_value = self.product_type_member_reader

        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product_type'], self.product_type)

    @patch('dojo.models.Product_Type_Member.objects.get')
    def test_user_has_permission_product_type_success(self, mock_get):
        mock_get.return_value = self.product_type_member_owner

        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product_type'], self.product_type)

    def test_user_has_permission_product_no_member(self):
        result = user_has_permission(self.user, self.product, Permissions.Product_View)
        self.assertFalse(result)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_product_no_permissions(self, mock_get):
        mock_get.return_value = self.product_member_reader

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Type_Member.objects.get')
    def test_user_has_permission_product_product_type_success(self, mock_get):
        mock_get.return_value = self.product_type_member_owner

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product_type'], self.product_type)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_product_success(self, mock_get):
        mock_get.return_value = self.product_member_owner

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_engagement_no_permissions(self, mock_get):
        mock_get.return_value = self.product_member_reader

        result = user_has_permission(self.user, self.engagement, Permissions.Engagement_Edit)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_engagement_success(self, mock_get):
        mock_get.return_value = self.product_member_owner

        result = user_has_permission(self.user, self.engagement, Permissions.Engagement_Delete)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_test_no_permissions(self, mock_get):
        mock_get.return_value = self.product_member_reader

        result = user_has_permission(self.user, self.test, Permissions.Test_Edit)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_test_success(self, mock_get):
        mock_get.return_value = self.product_member_owner

        result = user_has_permission(self.user, self.test, Permissions.Test_Delete)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_finding_no_permissions(self, mock_get):
        mock_get.return_value = self.product_member_reader

        result = user_has_permission(self.user, self.finding, Permissions.Finding_Edit)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_finding_success(self, mock_get):
        mock_get.return_value = self.product_member_owner

        result = user_has_permission(self.user, self.finding, Permissions.Finding_Delete)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_endpoint_no_permissions(self, mock_get):
        mock_get.return_value = self.product_member_reader

        result = user_has_permission(self.user, self.endpoint, Permissions.Endpoint_Edit)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_endpoint_success(self, mock_get):
        mock_get.return_value = self.product_member_owner

        result = user_has_permission(self.user, self.endpoint, Permissions.Endpoint_Delete)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], self.user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    def test_user_has_permission_product_type_member_success_same_user(self):
        result = user_has_permission(self.user, self.product_type_member_owner, Permissions.Product_Type_Remove_Member)
        self.assertTrue(result)

    @patch('dojo.models.Product_Type_Member.objects.get')
    def test_user_has_permission_product_type_member_no_permission(self, mock_get):
        other_user = User()
        product_type_member_other_user = Product_Type_Member()
        product_type_member_other_user.user = other_user
        product_type_member_other_user.product_type = self.product_type
        product_type_member_other_user.role = Roles.Reader
        mock_get.return_value = product_type_member_other_user

        result = user_has_permission(other_user, self.product_type_member_owner, Permissions.Product_Type_Remove_Member)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], other_user)
        self.assertEqual(mock_get.call_args[1]['product_type'], self.product_type)

    @patch('dojo.models.Product_Type_Member.objects.get')
    def test_user_has_permission_product_type_member_success(self, mock_get):
        other_user = User()
        product_type_member_other_user = Product_Type_Member()
        product_type_member_other_user.user = other_user
        product_type_member_other_user.product_type = self.product_type
        product_type_member_other_user.role = Roles.Owner
        mock_get.return_value = product_type_member_other_user

        result = user_has_permission(other_user, self.product_type_member_reader, Permissions.Product_Type_Remove_Member)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], other_user)
        self.assertEqual(mock_get.call_args[1]['product_type'], self.product_type)

    def test_user_has_permission_product_member_success_same_user(self):
        result = user_has_permission(self.user, self.product_member_owner, Permissions.Product_Remove_Member)
        self.assertTrue(result)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_product_member_no_permission(self, mock_get):
        other_user = User()
        product_member_other_user = Product_Member()
        product_member_other_user.user = other_user
        product_member_other_user.product = self.product
        product_member_other_user.role = Roles.Reader
        mock_get.return_value = product_member_other_user

        result = user_has_permission(other_user, self.product_member_owner, Permissions.Product_Remove_Member)

        self.assertFalse(result)
        self.assertEqual(mock_get.call_args[1]['user'], other_user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)

    @patch('dojo.models.Product_Member.objects.get')
    def test_user_has_permission_product_member_success(self, mock_get):
        other_user = User()
        product_member_other_user = Product_Member()
        product_member_other_user.user = other_user
        product_member_other_user.product_type = self.product
        product_member_other_user.role = Roles.Owner
        mock_get.return_value = product_member_other_user

        result = user_has_permission(other_user, self.product_member_reader, Permissions.Product_Remove_Member)

        self.assertTrue(result)
        self.assertEqual(mock_get.call_args[1]['user'], other_user)
        self.assertEqual(mock_get.call_args[1]['product'], self.product)
