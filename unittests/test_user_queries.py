from unittest.mock import patch
from .dojo_test_case import DojoTestCase
from dojo.authorization.roles_permissions import Permissions
from dojo.models import Dojo_User, Global_Role, Role, Product_Type, Product, Product_Type_Member, Product_Member
from dojo.user.queries import get_authorized_users


class TestUserQueries(DojoTestCase):

    def setUp(self):
        super().setUp()

        self.product_type_1 = Product_Type(name='product_type_1')
        self.product_type_1.save()
        self.product_1 = Product(name='product_1', prod_type=self.product_type_1)
        self.product_1.save()
        self.product_type_2 = Product_Type(name='product_type_2')
        self.product_type_2.save()
        self.product_2 = Product(name='product_2', prod_type=self.product_type_2)
        self.product_2.save()

        self.admin_user = Dojo_User(username='admin_user', is_superuser=True)
        self.admin_user.save()

        self.global_permission_user = Dojo_User(username='global_permission_user')
        self.global_permission_user.save()
        Global_Role(user=self.global_permission_user, role=Role.objects.get(name='Reader')).save()

        self.regular_user = Dojo_User(username='regular_user')
        self.regular_user.save()
        Product_Member(user=self.regular_user, product=self.product_1, role=Role.objects.get(name='Owner')).save()
        Product_Type_Member(user=self.regular_user, product_type=self.product_type_2, role=Role.objects.get(name='Writer')).save()

        self.product_user = Dojo_User(username='product_user')
        self.product_user.save()
        Product_Member(user=self.product_user, product=self.product_1, role=Role.objects.get(name='Reader')).save()

        self.product_type_user = Dojo_User(username='product_type_user')
        self.product_type_user.save()
        Product_Member(user=self.product_type_user, product=self.product_2, role=Role.objects.get(name='Maintainer')).save()

        self.invisible_user = Dojo_User(username='invisible_user')
        self.invisible_user.save()

    def tearDown(self):
        super().tearDown()
        self.product_type_1.delete()
        self.product_type_2.delete()
        self.admin_user.delete()
        self.global_permission_user.delete()
        self.regular_user.delete()
        self.product_user.delete()
        self.product_type_user.delete()
        self.invisible_user.delete()

    @patch('dojo.user.queries.get_current_user')
    def test_user_none(self, mock_current_user):
        mock_current_user.return_value = None

        self.assertQuerysetEqual(Dojo_User.objects.none(), get_authorized_users(Permissions.Product_View))

    @patch('dojo.user.queries.get_current_user')
    def test_user_admin(self, mock_current_user):
        mock_current_user.return_value = self.admin_user

        users = Dojo_User.objects.all().order_by('first_name', 'last_name', 'username')
        self.assertQuerysetEqual(users, get_authorized_users(Permissions.Product_View))

    @patch('dojo.user.queries.get_current_user')
    def test_user_global_permission(self, mock_current_user):
        mock_current_user.return_value = self.global_permission_user

        users = Dojo_User.objects.all().order_by('first_name', 'last_name', 'username')
        self.assertQuerysetEqual(users, get_authorized_users(Permissions.Product_View))

    @patch('dojo.user.queries.get_current_user')
    @patch('dojo.product.queries.get_current_user')
    def test_user_regular(self, mock_current_user_1, mock_current_user_2):
        mock_current_user_1.return_value = self.regular_user
        mock_current_user_2.return_value = self.regular_user

        users = Dojo_User.objects.exclude(username='invisible_user').order_by('first_name', 'last_name', 'username')
        self.assertQuerysetEqual(users, get_authorized_users(Permissions.Product_View))
