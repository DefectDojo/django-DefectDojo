from unittest.mock import patch

from dojo.authorization.models import (
    Dojo_Group_Member,
    Global_Role,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
    Role,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
    Dojo_Group,
    Dojo_User,
    Product,
    Product_Type,
)
from dojo.user.queries import (
    get_authorized_users,
    get_authorized_users_for_product_and_product_type,
    get_authorized_users_for_product_type,
)

from .dojo_test_case import DojoTestCase


class TestUserQueries(DojoTestCase):

    def setUp(self):
        super().setUp()

        self.product_type_1 = Product_Type(name="product_type_1")
        self.product_type_1.save()
        self.product_1 = Product(name="product_1", description="test", prod_type=self.product_type_1)
        self.product_1.save()
        self.product_type_2 = Product_Type(name="product_type_2")
        self.product_type_2.save()
        self.product_2 = Product(name="product_2", description="test", prod_type=self.product_type_2)
        self.product_2.save()

        self.admin_user = Dojo_User(username="admin_user", is_superuser=True)
        self.admin_user.save()

        self.global_permission_user = Dojo_User(username="global_permission_user")
        self.global_permission_user.save()
        Global_Role(user=self.global_permission_user, role=Role.objects.get(name="Reader")).save()

        self.regular_user = Dojo_User(username="regular_user")
        self.regular_user.save()
        Product_Member(user=self.regular_user, product=self.product_1, role=Role.objects.get(name="Owner")).save()
        Product_Type_Member(user=self.regular_user, product_type=self.product_type_2, role=Role.objects.get(name="Writer")).save()

        self.product_user = Dojo_User(username="product_user")
        self.product_user.save()
        Product_Member(user=self.product_user, product=self.product_1, role=Role.objects.get(name="Reader")).save()

        self.product_type_user = Dojo_User(username="product_type_user")
        self.product_type_user.save()
        Product_Member(user=self.product_type_user, product=self.product_2, role=Role.objects.get(name="Maintainer")).save()

        self.invisible_user = Dojo_User(username="invisible_user")
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

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_user_none(self, mock_current_user):
        mock_current_user.return_value = None

        self.assertQuerySetEqual(Dojo_User.objects.none(), get_authorized_users(Permissions.Product_View))

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_user_admin(self, mock_current_user):
        # Superuser: returns every Dojo_User in first_name/last_name order.
        mock_current_user.return_value = self.admin_user

        users = Dojo_User.objects.all().order_by("first_name", "last_name")
        self.assertQuerySetEqual(users, get_authorized_users(Permissions.Product_View))

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_user_global_permission_legacy(self, mock_current_user):
        # Legacy: Global_Role(role=Reader) is inert. The user has no
        # is_staff / is_superuser flag, so only their own row is returned.
        mock_current_user.return_value = self.global_permission_user

        self.assertQuerySetEqual(
            Dojo_User.objects.filter(pk=self.global_permission_user.pk),
            get_authorized_users(Permissions.Product_View),
        )

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_user_regular_legacy(self, mock_current_user):
        # Legacy: per-product RBAC role is inert. A non-staff non-superuser
        # only sees themselves.
        mock_current_user.return_value = self.regular_user

        self.assertQuerySetEqual(
            Dojo_User.objects.filter(pk=self.regular_user.pk),
            get_authorized_users(Permissions.Product_View),
        )


class TestGetAuthorizedUsersForProductType(DojoTestCase):

    """Tests for get_authorized_users_for_product_type()"""

    @classmethod
    def setUpTestData(cls):
        cls.reader_role = Role.objects.get(name="Reader")
        cls.writer_role = Role.objects.get(name="Writer")

        # Create users with different permission levels
        cls.superuser = Dojo_User.objects.create(
            username="uq_pt_superuser",
            is_superuser=True,
            is_active=True,
        )
        cls.user_no_perms = Dojo_User.objects.create(
            username="uq_pt_no_perms",
            is_active=True,
        )
        cls.user_product_type_member = Dojo_User.objects.create(
            username="uq_pt_member",
            is_active=True,
        )
        cls.user_global_reader = Dojo_User.objects.create(
            username="uq_pt_global_reader",
            is_active=True,
        )
        cls.user_group_member = Dojo_User.objects.create(
            username="uq_pt_group_member",
            is_active=True,
        )

        # Create product type
        cls.product_type = Product_Type.objects.create(name="UQ Test PT")

        # Set up memberships
        Product_Type_Member.objects.create(
            user=cls.user_product_type_member,
            product_type=cls.product_type,
            role=cls.reader_role,
        )
        Global_Role.objects.create(
            user=cls.user_global_reader,
            role=cls.reader_role,
        )

        # Create group and group membership
        cls.group = Dojo_Group.objects.create(name="UQ PT Test Group")
        Dojo_Group_Member.objects.create(
            user=cls.user_group_member,
            group=cls.group,
            role=cls.reader_role,
        )
        Product_Type_Group.objects.create(
            product_type=cls.product_type,
            group=cls.group,
            role=cls.reader_role,
        )

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_superuser_caller_sees_all(self, mock_get_current_user):
        # Legacy: this query is gated on the calling user, not on the
        # listed users' RBAC roles. A superuser caller sees the input
        # queryset unchanged.
        mock_get_current_user.return_value = self.superuser
        users = get_authorized_users_for_product_type(
            Dojo_User.objects.all(),
            self.product_type,
            Permissions.Product_Type_View,
        )
        self.assertIn(self.superuser, users)
        self.assertIn(self.user_no_perms, users)
        self.assertIn(self.user_global_reader, users)

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_non_staff_caller_sees_none(self, mock_get_current_user):
        # Legacy: a non-staff non-superuser caller can't enumerate users
        # for a product_type — including users with explicit memberships.
        mock_get_current_user.return_value = self.user_product_type_member
        users = get_authorized_users_for_product_type(
            Dojo_User.objects.all(),
            self.product_type,
            Permissions.Product_Type_View,
        )
        self.assertEqual(users.count(), 0)

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_anonymous_caller_sees_none(self, mock_get_current_user):
        mock_get_current_user.return_value = None
        users = get_authorized_users_for_product_type(
            Dojo_User.objects.all(),
            self.product_type,
            Permissions.Product_Type_View,
        )
        self.assertEqual(users.count(), 0)


class TestGetAuthorizedUsersForProductAndProductType(DojoTestCase):

    """Tests for get_authorized_users_for_product_and_product_type()"""

    @classmethod
    def setUpTestData(cls):
        cls.reader_role = Role.objects.get(name="Reader")
        cls.writer_role = Role.objects.get(name="Writer")

        # Create users with different permission levels
        cls.superuser = Dojo_User.objects.create(
            username="uq_ppt_superuser",
            is_superuser=True,
            is_active=True,
        )
        cls.user_no_perms = Dojo_User.objects.create(
            username="uq_ppt_no_perms",
            is_active=True,
        )
        cls.user_product_member = Dojo_User.objects.create(
            username="uq_ppt_prod_member",
            is_active=True,
        )
        cls.user_product_type_member = Dojo_User.objects.create(
            username="uq_ppt_pt_member",
            is_active=True,
        )
        cls.user_global_reader = Dojo_User.objects.create(
            username="uq_ppt_global_reader",
            is_active=True,
        )
        cls.user_group_product_member = Dojo_User.objects.create(
            username="uq_ppt_group_prod_member",
            is_active=True,
        )
        cls.user_group_product_type_member = Dojo_User.objects.create(
            username="uq_ppt_group_pt_member",
            is_active=True,
        )

        # Create product type and product
        cls.product_type = Product_Type.objects.create(name="UQ PPT Test PT")
        cls.product = Product.objects.create(
            name="UQ PPT Test Product",
            description="Test",
            prod_type=cls.product_type,
        )

        # Set up direct memberships
        Product_Member.objects.create(
            user=cls.user_product_member,
            product=cls.product,
            role=cls.reader_role,
        )
        Product_Type_Member.objects.create(
            user=cls.user_product_type_member,
            product_type=cls.product_type,
            role=cls.reader_role,
        )
        Global_Role.objects.create(
            user=cls.user_global_reader,
            role=cls.reader_role,
        )

        # Create groups and group memberships
        cls.group_product = Dojo_Group.objects.create(name="UQ PPT Product Group")
        cls.group_product_type = Dojo_Group.objects.create(name="UQ PPT Product Type Group")

        Dojo_Group_Member.objects.create(
            user=cls.user_group_product_member,
            group=cls.group_product,
            role=cls.reader_role,
        )
        Dojo_Group_Member.objects.create(
            user=cls.user_group_product_type_member,
            group=cls.group_product_type,
            role=cls.reader_role,
        )

        Product_Group.objects.create(
            product=cls.product,
            group=cls.group_product,
            role=cls.reader_role,
        )
        Product_Type_Group.objects.create(
            product_type=cls.product_type,
            group=cls.group_product_type,
            role=cls.reader_role,
        )

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_superuser_caller_sees_all(self, mock_get_current_user):
        # Legacy: gated on the calling user. None defaults to all users.
        mock_get_current_user.return_value = self.superuser
        users = get_authorized_users_for_product_and_product_type(
            None,
            self.product,
            Permissions.Product_View,
        )
        self.assertIn(self.superuser, users)
        self.assertIn(self.user_no_perms, users)
        self.assertIn(self.user_global_reader, users)

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_non_staff_caller_sees_none(self, mock_get_current_user):
        mock_get_current_user.return_value = self.user_product_member
        users = get_authorized_users_for_product_and_product_type(
            None,
            self.product,
            Permissions.Product_View,
        )
        self.assertEqual(users.count(), 0)

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_anonymous_caller_sees_none(self, mock_get_current_user):
        mock_get_current_user.return_value = None
        users = get_authorized_users_for_product_and_product_type(
            None,
            self.product,
            Permissions.Product_View,
        )
        self.assertEqual(users.count(), 0)

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_users_parameter_filters_base_queryset(self, mock_get_current_user):
        # Legacy: when the caller is staff/superuser, the function returns
        # the input queryset unchanged — the caller's pre-filter (here
        # is_active=True) is preserved.
        mock_get_current_user.return_value = self.superuser
        active_users = Dojo_User.objects.filter(is_active=True)
        users = get_authorized_users_for_product_and_product_type(
            active_users,
            self.product,
            Permissions.Product_View,
        )
        for user in users:
            self.assertTrue(user.is_active)
