from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.test.utils import override_settings
from ..dojo_test_case import DojoTestCase
from unittest.mock import patch
from dojo.models import Dojo_User, Product_Type, Product_Type_Member, Product, Product_Member, Engagement, \
    Test, Finding, Endpoint, Dojo_Group, Product_Group, Product_Type_Group, Role, Global_Role, Dojo_Group_Member, \
    Languages, App_Analysis, Stub_Finding
import dojo.authorization.authorization
from dojo.authorization.authorization import role_has_permission, get_roles_for_permission, user_has_global_permission, \
    user_has_permission_or_403, user_has_permission, user_has_configuration_permission, \
    RoleDoesNotExistError, PermissionDoesNotExistError
from dojo.authorization.roles_permissions import Permissions, Roles


class TestAuthorization(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User()
        cls.user.id = 1

        cls.user2 = Dojo_User()
        cls.user2.id = 2
        cls.global_role_user = Global_Role()
        cls.global_role_user.id = 1
        cls.global_role_user.user = cls.user2
        cls.global_role_user.role = Role.objects.get(id=Roles.Reader)

        cls.product_type = Product_Type()
        cls.product_type.id = 1
        cls.product_type_member = Product_Type_Member()
        cls.product_type_member.id = 1

        cls.product = Product()
        cls.product.id = 1
        cls.product_member = Product_Member()
        cls.product_member.id = 1
        cls.product.prod_type = cls.product_type

        cls.engagement = Engagement()
        cls.engagement.product = cls.product

        cls.test = Test()
        cls.test.engagement = cls.engagement

        cls.finding = Finding()
        cls.finding.test = cls.test

        cls.stub_finding = Stub_Finding()
        cls.stub_finding.test = cls.test

        cls.endpoint = Endpoint()
        cls.endpoint.product = cls.product

        cls.technology = App_Analysis()
        cls.technology.product = cls.product

        cls.language = Languages()
        cls.language.product = cls.product

        cls.product_type_member_reader = Product_Type_Member()
        cls.product_type_member_reader.user = cls.user
        cls.product_type_member_reader.product_type = cls.product_type
        cls.product_type_member_reader.role = Role.objects.get(id=Roles.Reader)

        cls.product_type_member_owner = Product_Type_Member()
        cls.product_type_member_owner.user = cls.user
        cls.product_type_member_owner.product_type = cls.product_type
        cls.product_type_member_owner.role = Role.objects.get(id=Roles.Owner)

        cls.product_member_reader = Product_Member()
        cls.product_member_reader.user = cls.user
        cls.product_member_reader.product = cls.product
        cls.product_member_reader.role = Role.objects.get(id=Roles.Reader)

        cls.product_member_owner = Product_Member()
        cls.product_member_owner.user = cls.user
        cls.product_member_owner.product = cls.product
        cls.product_member_owner.role = Role.objects.get(id=Roles.Owner)

        cls.group = Dojo_Group()
        cls.group.id = 1

        cls.product_group_reader = Product_Group()
        cls.product_group_reader.id = 1
        cls.product_group_reader.product = cls.product
        cls.product_group_reader.group = cls.group
        cls.product_group_reader.role = Role.objects.get(id=Roles.Reader)

        cls.product_group_owner = Product_Group()
        cls.product_group_owner.id = 2
        cls.product_group_owner.product = cls.product
        cls.product_group_owner.group = cls.group
        cls.product_group_owner.role = Role.objects.get(id=Roles.Owner)

        cls.product_type_group_reader = Product_Type_Group()
        cls.product_type_group_reader.id = 1
        cls.product_type_group_reader.product_type = cls.product_type
        cls.product_type_group_reader.group = cls.group
        cls.product_type_group_reader.role = Role.objects.get(id=Roles.Reader)

        cls.product_type_group_owner = Product_Type_Group()
        cls.product_type_group_owner.id = 2
        cls.product_type_group_owner.product_type = cls.product_type
        cls.product_type_group_owner.group = cls.group
        cls.product_type_group_owner.role = Role.objects.get(id=Roles.Owner)

        cls.group2 = Dojo_Group()
        cls.group2.id = 2
        cls.global_role_group = Global_Role()
        cls.global_role_group.id = 2
        cls.global_role_group.group = cls.group2
        cls.global_role_group.role = Role.objects.get(id=Roles.Maintainer)

        cls.user3 = Dojo_User()
        cls.user3.id = 3
        cls.global_role_user = Global_Role()
        cls.global_role_user.id = 3
        cls.global_role_user.user = cls.user3
        cls.global_role_user.role = None

        cls.group3 = Dojo_Group()
        cls.group3.id = 3

        cls.user4 = Dojo_User()
        cls.user4.id = 4

        cls.group_member = Dojo_Group_Member()
        cls.group_member.id = 1
        cls.group_member.group = cls.group3
        cls.group_member.user = cls.user4
        cls.group_member.role = Role.objects.get(id=Roles.Writer)

        cls.user5 = Dojo_User()
        cls.user5.id = 5
        cls.global_role_user = Global_Role()
        cls.global_role_user.id = 5
        cls.global_role_user.user = cls.user5
        cls.global_role_user.role = Role.objects.get(id=Roles.Owner)

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

    @patch('dojo.models.Product_Type_Member.objects')
    def test_user_has_permission_or_403_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_type_member_owner]

        user_has_permission_or_403(self.user, self.product_type, Permissions.Product_Type_Delete)

        mock_foo.filter.assert_called_with(user=self.user)

    def test_user_has_permission_exception(self):
        with self.assertRaisesMessage(dojo.authorization.authorization.NoAuthorizationImplementedError,
                'No authorization implemented for class Product_Type_Member and permission 1007'):
            user_has_permission(self.user, self.product_type_member, Permissions.Product_Type_Delete)

    def test_user_has_permission_product_type_no_member(self):
        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_View)
        self.assertFalse(result)

    @patch('dojo.models.Product_Type_Member.objects')
    def test_user_has_permission_product_type_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_type_member_reader]

        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    def test_user_has_permission_superuser(self):
        self.user.is_superuser = True

        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertTrue(result)

        self.user.is_superuser = False

    @patch('dojo.models.Product_Type_Member.objects')
    def test_user_has_permission_product_type_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_type_member_owner]

        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    def test_user_has_permission_product_no_member(self):
        result = user_has_permission(self.user, self.product, Permissions.Product_View)
        self.assertFalse(result)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_product_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Type_Member.objects')
    def test_user_has_permission_product_product_type_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_type_member_owner]

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_product_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_engagement_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.engagement, Permissions.Engagement_Edit)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_engagement_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.engagement, Permissions.Engagement_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_test_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.test, Permissions.Test_Edit)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_test_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.test, Permissions.Test_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_finding_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.finding, Permissions.Finding_Edit)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_finding_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.finding, Permissions.Finding_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_stub_finding_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.stub_finding, Permissions.Finding_Edit)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_stub_finding_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.stub_finding, Permissions.Finding_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_endpoint_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.endpoint, Permissions.Endpoint_Edit)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_endpoint_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.endpoint, Permissions.Endpoint_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    def test_user_has_permission_product_type_member_success_same_user(self):
        result = user_has_permission(self.user, self.product_type_member_owner, Permissions.Product_Type_Member_Delete)
        self.assertTrue(result)

    @patch('dojo.models.Product_Type_Member.objects')
    def test_user_has_permission_product_type_member_no_permission(self, mock_foo):
        other_user = User()
        other_user.id = 2
        product_type_member_other_user = Product_Type_Member()
        product_type_member_other_user.id = 2
        product_type_member_other_user.user = other_user
        product_type_member_other_user.product_type = self.product_type
        product_type_member_other_user.role = Role.objects.get(id=Roles.Reader)
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [product_type_member_other_user]

        result = user_has_permission(other_user, self.product_type_member_owner, Permissions.Product_Type_Member_Delete)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=other_user)

    @patch('dojo.models.Product_Type_Member.objects')
    def test_user_has_permission_product_type_member_success(self, mock_foo):
        other_user = User()
        other_user.id = 2
        product_type_member_other_user = Product_Type_Member()
        product_type_member_other_user.id = 2
        product_type_member_other_user.user = other_user
        product_type_member_other_user.product_type = self.product_type
        product_type_member_other_user.role = Role.objects.get(id=Roles.Owner)
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [product_type_member_other_user]

        result = user_has_permission(other_user, self.product_type_member_reader, Permissions.Product_Type_Member_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=other_user)

    def test_user_has_permission_product_member_success_same_user(self):
        result = user_has_permission(self.user, self.product_member_owner, Permissions.Product_Member_Delete)
        self.assertTrue(result)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_product_member_no_permission(self, mock_foo):
        other_user = User()
        other_user.id = 2
        product_member_other_user = Product_Member()
        product_member_other_user.id = 2
        product_member_other_user.user = other_user
        product_member_other_user.product = self.product
        product_member_other_user.role = Role.objects.get(id=Roles.Reader)
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [product_member_other_user]

        result = user_has_permission(other_user, self.product_member_owner, Permissions.Product_Member_Delete)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=other_user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_product_member_success(self, mock_foo):
        other_user = User()
        other_user.id = 2
        product_member_other_user = Product_Member()
        product_member_other_user.id = 2
        product_member_other_user.user = other_user
        product_member_other_user.product = self.product
        product_member_other_user.role = Role.objects.get(id=Roles.Owner)
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [product_member_other_user]

        result = user_has_permission(other_user, self.product_member_reader, Permissions.Product_Member_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=other_user)

    @patch('dojo.models.Product_Group.objects')
    def test_user_has_group_product_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_group_reader]

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(group__users=self.user)

    @patch('dojo.models.Product_Group.objects')
    def test_user_has_group_product_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_group_owner]

        result = user_has_permission(self.user, self.product, Permissions.Product_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(group__users=self.user)

    @patch('dojo.models.Product_Type_Group.objects')
    def test_user_has_group_product_type_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_type_group_reader]

        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(group__users=self.user)

    @patch('dojo.models.Product_Type_Group.objects')
    def test_user_has_group_product_type_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_type_group_owner]

        result = user_has_permission(self.user, self.product_type, Permissions.Product_Type_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(group__users=self.user)

    def test_user_has_global_role_no_permission(self):
        result = user_has_permission(self.user2, self.product, Permissions.Product_Delete)
        self.assertFalse(result)

    def test_user_has_global_role_success(self):
        result = user_has_permission(self.user2, self.product, Permissions.Product_View)
        self.assertTrue(result)

    def test_user_has_global_role_global_permission_no_permission(self):
        result = user_has_global_permission(self.user2, Permissions.Product_Type_Add)
        self.assertFalse(result)

    def test_user_has_global_role_global_permission_success(self):
        result = user_has_global_permission(self.user5, Permissions.Product_Type_Add)
        self.assertTrue(result)

    @patch('dojo.models.Dojo_Group.objects')
    def test_user_in_group_with_global_role_no_permission(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.group2]

        result = user_has_permission(self.user3, self.product, Permissions.Product_Delete)
        self.assertFalse(result)
        mock_foo.filter.assert_called_with(users=self.user3)

    @patch('dojo.models.Dojo_Group.objects')
    def test_user_in_group_with_global_role_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.group2]

        result = user_has_permission(self.user3, self.product, Permissions.Product_Edit)
        self.assertTrue(result)
        mock_foo.filter.assert_called_with(users=self.user3)

    @patch('dojo.models.Dojo_Group_Member.objects')
    def test_dojo_group_no_permission(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.group_member]

        result = user_has_permission(self.user4, self.group3, Permissions.Group_Edit)
        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user4)

    @patch('dojo.models.Dojo_Group_Member.objects')
    def test_dojo_group_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.group_member]

        result = user_has_permission(self.user4, self.group3, Permissions.Group_View)
        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user4)

    @patch('dojo.models.Dojo_Group_Member.objects')
    def test_dojo_group_member_no_permission(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.group_member]

        result = user_has_permission(self.user4, self.group_member, Permissions.Group_Manage_Members)
        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user4)

    @patch('dojo.models.Dojo_Group_Member.objects')
    def test_dojo_group_member_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.group_member]

        result = user_has_permission(self.user4, self.group_member, Permissions.Group_View)
        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user4)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_language_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.language, Permissions.Language_Edit)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_language_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.language, Permissions.Language_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_technology_no_permissions(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_reader]

        result = user_has_permission(self.user, self.technology, Permissions.Technology_Edit)

        self.assertFalse(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @patch('dojo.models.Product_Member.objects')
    def test_user_has_permission_technology_success(self, mock_foo):
        mock_foo.select_related.return_value = mock_foo
        mock_foo.select_related.return_value = mock_foo
        mock_foo.filter.return_value = [self.product_member_owner]

        result = user_has_permission(self.user, self.technology, Permissions.Technology_Delete)

        self.assertTrue(result)
        mock_foo.filter.assert_called_with(user=self.user)

    @override_settings(FEATURE_CONFIGURATION_AUTHORIZATION=False)
    def test_configuration_permission_legacy_staff(self):
        self.user.is_staff = True
        self.assertTrue(user_has_configuration_permission(self.user, None, 'staff'))
        self.user.is_staff = False

    @override_settings(FEATURE_CONFIGURATION_AUTHORIZATION=False)
    def test_configuration_permission_legacy_superuser(self):
        self.user.is_superuser = True
        self.assertTrue(user_has_configuration_permission(self.user, None, 'superuser'))
        self.user.is_superuser = False

    @override_settings(FEATURE_CONFIGURATION_AUTHORIZATION=False)
    def test_configuration_permission_legacy_exception(self):
        with self.assertRaisesMessage(Exception, 'test is not allowed for parameter legacy'):
            user_has_configuration_permission(self.user, None, 'test')

    @override_settings(FEATURE_CONFIGURATION_AUTHORIZATION=True)
    @patch('django.contrib.auth.models.User.has_perm')
    def test_configuration_permission_true(self, mock):
        mock.return_value = True
        self.assertTrue(user_has_configuration_permission(self.user, 'test', 'test'))
        mock.assert_called_with('test')

    @override_settings(FEATURE_CONFIGURATION_AUTHORIZATION=True)
    @patch('django.contrib.auth.models.User.has_perm')
    def test_configuration_permission_false(self, mock):
        mock.return_value = False
        self.assertFalse(user_has_configuration_permission(self.user, 'test', 'test'))
        mock.assert_called_with('test')
