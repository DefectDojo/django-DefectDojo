from unittest.mock import patch

from dojo.authorization.models import (
    Global_Role,
    Product_Member,
    Product_Type_Member,
    Role,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
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
        # Carrier Global_Role(role=Reader) is inert in OS. Without any
        # authorized_users membership the user sees only superusers (always
        # surfaced, matching 2.58.4).
        mock_current_user.return_value = self.global_permission_user

        self.assertQuerySetEqual(
            Dojo_User.objects.filter(is_superuser=True).order_by("first_name", "last_name"),
            get_authorized_users(Permissions.Product_View),
        )

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_user_regular_legacy(self, mock_current_user):
        # Carrier Product_Member / Product_Type_Member are inert in OS. Without
        # any authorized_users membership the user sees only superusers.
        mock_current_user.return_value = self.regular_user

        self.assertQuerySetEqual(
            Dojo_User.objects.filter(is_superuser=True).order_by("first_name", "last_name"),
            get_authorized_users(Permissions.Product_View),
        )

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_user_collaborators_via_authorized_users(self, mock_current_user):
        # v2 parity: a non-staff user sees co-members of the products/types
        # they are authorized on (via authorized_users), plus superusers.
        self.product_1.authorized_users.add(self.regular_user)
        self.product_1.authorized_users.add(self.product_user)
        mock_current_user.return_value = self.regular_user

        users = get_authorized_users(Permissions.Product_View)
        self.assertIn(self.regular_user, users)
        self.assertIn(self.product_user, users)
        self.assertIn(self.admin_user, users)
        self.assertNotIn(self.invisible_user, users)


class TestGetAuthorizedUsersForProductType(DojoTestCase):

    """Tests for get_authorized_users_for_product_type()"""

    @classmethod
    def setUpTestData(cls):
        cls.superuser = Dojo_User.objects.create(username="uq_pt_superuser", is_superuser=True, is_active=True)
        cls.staff = Dojo_User.objects.create(username="uq_pt_staff", is_staff=True, is_active=True)
        cls.user_no_perms = Dojo_User.objects.create(username="uq_pt_no_perms", is_active=True)
        cls.user_product_type_member = Dojo_User.objects.create(username="uq_pt_member", is_active=True)

        cls.product_type = Product_Type.objects.create(name="UQ Test PT")
        cls.product_type.authorized_users.add(cls.user_product_type_member)

    def _users(self, caller, users=None):
        with patch("dojo.authorization.query_registrations.get_current_user", return_value=caller):
            return list(get_authorized_users_for_product_type(users, self.product_type, Permissions.Product_Type_View))

    def test_result_describes_the_listed_users_not_the_caller(self):
        # The same candidate set comes back whoever asks: the members of the
        # product type plus superusers, never the unrelated users.
        for caller in (self.superuser, self.staff, self.user_product_type_member, self.user_no_perms, None):
            with self.subTest(caller=caller):
                users = self._users(caller)
                self.assertIn(self.superuser, users)
                self.assertIn(self.user_product_type_member, users)
                self.assertNotIn(self.user_no_perms, users)
                self.assertNotIn(self.staff, users)

    def test_users_parameter_filters_base_queryset(self):
        users = self._users(self.superuser, Dojo_User.objects.filter(is_superuser=False))
        self.assertEqual([self.user_product_type_member], users)

    def test_no_product_type_returns_nobody(self):
        with patch("dojo.authorization.query_registrations.get_current_user", return_value=self.superuser):
            self.assertEqual(0, get_authorized_users_for_product_type(None, None, Permissions.Product_Type_View).count())


class TestGetAuthorizedUsersForProductAndProductType(DojoTestCase):

    """Tests for get_authorized_users_for_product_and_product_type()"""

    @classmethod
    def setUpTestData(cls):
        cls.superuser = Dojo_User.objects.create(username="uq_ppt_superuser", is_superuser=True, is_active=True)
        cls.staff = Dojo_User.objects.create(username="uq_ppt_staff", is_staff=True, is_active=True)
        cls.user_no_perms = Dojo_User.objects.create(username="uq_ppt_no_perms", is_active=True)
        cls.user_product_member = Dojo_User.objects.create(username="uq_ppt_prod_member", is_active=True)
        cls.user_product_type_member = Dojo_User.objects.create(username="uq_ppt_pt_member", is_active=True)

        cls.product_type = Product_Type.objects.create(name="UQ PPT Test PT")
        cls.product = Product.objects.create(name="UQ PPT Test Product", description="Test", prod_type=cls.product_type)
        cls.product.authorized_users.add(cls.user_product_member)
        cls.product_type.authorized_users.add(cls.user_product_type_member)

    def _users(self, caller, users=None):
        with patch("dojo.authorization.query_registrations.get_current_user", return_value=caller):
            return list(get_authorized_users_for_product_and_product_type(users, self.product, Permissions.Product_View))

    def test_result_describes_the_listed_users_not_the_caller(self):
        for caller in (self.superuser, self.staff, self.user_product_member, self.user_no_perms, None):
            with self.subTest(caller=caller):
                users = self._users(caller)
                self.assertIn(self.superuser, users)
                self.assertIn(self.user_product_member, users)
                self.assertIn(self.user_product_type_member, users)
                self.assertNotIn(self.user_no_perms, users)
                self.assertNotIn(self.staff, users)

    def test_users_parameter_filters_base_queryset(self):
        users = self._users(self.superuser, Dojo_User.objects.filter(is_active=True, is_superuser=False))
        self.assertEqual({self.user_product_member, self.user_product_type_member}, set(users))

    def test_no_product_returns_nobody(self):
        with patch("dojo.authorization.query_registrations.get_current_user", return_value=self.superuser):
            self.assertEqual(0, get_authorized_users_for_product_and_product_type(None, None, Permissions.Product_View).count())


class TestGetAuthorizedUsersViaAuthorizedUsers(DojoTestCase):

    """
    OS authorized_users-based resolution for the product / product-type user
    queries (regression test for issue #15062 — empty Testing Lead selector).
    """

    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name="AU Test PT")
        cls.product = Product.objects.create(
            name="AU Test Product", description="t", prod_type=cls.product_type,
        )

        cls.product_member = Dojo_User.objects.create(username="au_product_member", is_active=True)
        cls.product_type_member = Dojo_User.objects.create(username="au_pt_member", is_active=True)
        cls.unrelated = Dojo_User.objects.create(username="au_unrelated", is_active=True)
        # Superuser not in any authorized_users — must still surface (2.58.4 parity).
        cls.superuser = Dojo_User.objects.create(username="au_superuser", is_active=True, is_superuser=True)

        # The "authorized users" sections the reporter used in the UI.
        cls.product.authorized_users.add(cls.product_member)
        cls.product_type.authorized_users.add(cls.product_type_member)

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_product_and_product_type_returns_authorized_users(self, mock_get_current_user):
        # #15062: a non-staff user authorized on the product (via authorized_users)
        # must get a non-empty list so they can pick a Testing Lead. The list
        # contains users authorized directly on the product and via its type,
        # plus superusers (2.58.4 parity).
        mock_get_current_user.return_value = self.product_member
        users = get_authorized_users_for_product_and_product_type(
            None, self.product, Permissions.Product_View,
        )
        self.assertIn(self.product_member, users)
        self.assertIn(self.product_type_member, users)
        self.assertIn(self.superuser, users)
        self.assertNotIn(self.unrelated, users)

    @patch("dojo.authorization.query_registrations.get_current_user")
    def test_product_type_returns_authorized_users(self, mock_get_current_user):
        mock_get_current_user.return_value = self.product_type_member
        users = get_authorized_users_for_product_type(
            None, self.product_type, Permissions.Product_Type_View,
        )
        self.assertIn(self.product_type_member, users)
        self.assertIn(self.superuser, users)
        self.assertNotIn(self.product_member, users)
        self.assertNotIn(self.unrelated, users)
