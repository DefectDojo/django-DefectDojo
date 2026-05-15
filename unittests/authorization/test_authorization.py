"""
Legacy (pre-2020) authorization tests.

These tests cover the actual contract of dojo.authorization.authorization
after the Track B legacy rewrite:

  * is_superuser → bypass everything
  * is_staff     → bypass everything (matches the pre-2020 model in
                   dojo/user/helper.py at commit e7805aa14~)
  * authorized_users membership on the closest authorization-bearing
    parent (Product or Product_Type, with Product_Type cascading to its
    products)
  * carrier objects (Engagement / Test / Finding / Finding_Group /
    Endpoint / etc.) delegate to their wrapping product
  * Action.SuperuserOnly always denies non-superusers
  * Action.Delete / Action.StaffOnly require is_staff
  * Member rows (Product_Member / Product_Type_Member / Dojo_Group_Member)
    permit self-removal regardless of membership

The fine-grained Permissions enum is preserved as a back-compat input
shape; it maps through permission_to_action() to the legacy Action
vocabulary.

The role-based helpers (role_has_permission, get_roles_for_permission)
are inert stubs in the legacy model — they exist only so transitional
callers don't AttributeError. Tests below verify the stub contract
(empty/False return, no exceptions).
"""
import datetime
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from dojo.authorization.authorization import (
    NoAuthorizationImplementedError,
    get_roles_for_permission,
    role_has_global_permission,
    role_has_permission,
    user_has_configuration_permission,
    user_has_global_permission,
    user_has_permission,
    user_has_permission_or_403,
)
from dojo.authorization.roles_permissions import Action, Permissions, Roles
from dojo.models import (
    Dojo_Group,
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from unittests.dojo_test_case import DojoTestCase


class LegacyAuthorizationBaseTestCase(DojoTestCase):

    """
    Shared fixtures: two products under two product_types, a member,
    an outsider, a staff user, and a superuser. Membership is established
    via Product.authorized_users / Product_Type.authorized_users only —
    no Product_Member rows are involved.
    """

    @classmethod
    def setUpTestData(cls):
        cls.pt_alpha = Product_Type.objects.create(name="auth_test_pt_alpha")
        cls.pt_beta = Product_Type.objects.create(name="auth_test_pt_beta")
        cls.alpha = Product.objects.create(name="auth_test_alpha", description="x", prod_type=cls.pt_alpha)
        cls.beta = Product.objects.create(name="auth_test_beta", description="x", prod_type=cls.pt_beta)

        cls.member = Dojo_User.objects.create(username="auth_test_member")
        cls.cascade_user = Dojo_User.objects.create(username="auth_test_cascade")
        cls.outsider = Dojo_User.objects.create(username="auth_test_outsider")
        cls.staff = Dojo_User.objects.create(username="auth_test_staff", is_staff=True)
        cls.superuser = Dojo_User.objects.create(username="auth_test_superuser", is_superuser=True)

        # Direct product membership on alpha
        cls.alpha.authorized_users.add(cls.member)
        # Cascade via product_type membership on beta_type → beta
        cls.pt_beta.authorized_users.add(cls.cascade_user)


class TestUserHasPermissionLegacy(LegacyAuthorizationBaseTestCase):

    """Object-level permission via legacy authorized_users membership."""

    # ---- anonymous / None user --------------------------------------------

    def test_anonymous_user_denied(self):
        self.assertFalse(user_has_permission(None, self.alpha, "view"))

    def test_anonymous_django_user_denied(self):
        self.assertFalse(user_has_permission(AnonymousUser(), self.alpha, "view"))

    # ---- superuser bypass --------------------------------------------------

    def test_superuser_bypass_view(self):
        self.assertTrue(user_has_permission(self.superuser, self.alpha, "view"))

    def test_superuser_bypass_delete(self):
        self.assertTrue(user_has_permission(self.superuser, self.alpha, Permissions.Product_Delete))

    def test_superuser_bypass_staff_only(self):
        self.assertTrue(user_has_permission(self.superuser, self.alpha, Action.StaffOnly))

    # ---- staff bypass (historical pre-2020 behavior) ----------------------

    def test_staff_bypasses_view(self):
        # Staff sees products they aren't a member of — matches pre-2020.
        self.assertTrue(user_has_permission(self.staff, self.alpha, "view"))
        self.assertTrue(user_has_permission(self.staff, self.beta, "view"))

    def test_staff_bypasses_edit(self):
        self.assertTrue(user_has_permission(self.staff, self.alpha, "edit"))

    def test_staff_can_delete(self):
        self.assertTrue(user_has_permission(self.staff, self.alpha, Permissions.Product_Delete))

    def test_staff_can_staff_only(self):
        self.assertTrue(user_has_permission(self.staff, self.alpha, Action.StaffOnly))

    # ---- direct product membership ----------------------------------------

    def test_member_view_own_product(self):
        self.assertTrue(user_has_permission(self.member, self.alpha, "view"))

    def test_member_edit_own_product(self):
        # Legacy collapses Reader/Writer/Maintainer/Owner into one bit:
        # if you're in authorized_users, you can edit.
        self.assertTrue(user_has_permission(self.member, self.alpha, "edit"))

    def test_member_view_other_product(self):
        self.assertFalse(user_has_permission(self.member, self.beta, "view"))

    def test_member_cannot_delete(self):
        # Delete is always staff/superuser only in legacy.
        self.assertFalse(user_has_permission(self.member, self.alpha, Permissions.Product_Delete))

    def test_member_cannot_staff_only(self):
        self.assertFalse(user_has_permission(self.member, self.alpha, Action.StaffOnly))

    # ---- product_type cascade ---------------------------------------------

    def test_product_type_member_sees_product_type(self):
        self.assertTrue(user_has_permission(self.cascade_user, self.pt_beta, "view"))

    def test_product_type_member_cascades_to_product(self):
        self.assertTrue(user_has_permission(self.cascade_user, self.beta, "view"))

    def test_product_type_member_does_not_cross_types(self):
        self.assertFalse(user_has_permission(self.cascade_user, self.alpha, "view"))
        self.assertFalse(user_has_permission(self.cascade_user, self.pt_alpha, "view"))

    # ---- outsider ----------------------------------------------------------

    def test_outsider_no_access(self):
        self.assertFalse(user_has_permission(self.outsider, self.alpha, "view"))
        self.assertFalse(user_has_permission(self.outsider, self.beta, "view"))


class TestCarrierObjectsDelegateToProduct(LegacyAuthorizationBaseTestCase):

    """Engagement, Test, Finding all resolve via their product."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.eng = Engagement.objects.create(
            product=cls.alpha, name="auth_eng",
            target_start=datetime.date.today(), target_end=datetime.date.today(),
        )
        tt, _ = Test_Type.objects.get_or_create(name="Manual Test")
        cls.test = Test.objects.create(
            engagement=cls.eng, test_type=tt,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        cls.finding = Finding.objects.create(
            test=cls.test, title="auth_finding", reporter=cls.member,
            severity="High", description="x", mitigation="x", impact="x",
        )

    def test_member_can_view_engagement_under_alpha(self):
        self.assertTrue(user_has_permission(self.member, self.eng, "view"))

    def test_member_can_view_test_under_alpha(self):
        self.assertTrue(user_has_permission(self.member, self.test, "view"))

    def test_member_can_view_finding_under_alpha(self):
        self.assertTrue(user_has_permission(self.member, self.finding, "view"))

    def test_outsider_cannot_view_engagement(self):
        self.assertFalse(user_has_permission(self.outsider, self.eng, "view"))

    def test_outsider_cannot_view_finding(self):
        self.assertFalse(user_has_permission(self.outsider, self.finding, "view"))


class TestUserHasPermissionInputForms(LegacyAuthorizationBaseTestCase):

    """
    user_has_permission accepts Permissions enum, Action enum, action
    string, and legacy enum-name strings — all funnel through
    permission_to_action().
    """

    def test_action_string(self):
        self.assertTrue(user_has_permission(self.member, self.alpha, "view"))

    def test_permissions_enum_member(self):
        self.assertTrue(user_has_permission(self.member, self.alpha, Permissions.Product_View))

    def test_action_enum_member(self):
        self.assertTrue(user_has_permission(self.member, self.alpha, Action.View))

    def test_legacy_enum_name_string(self):
        # Old call sites still pass strings like "Product_View" — we accept them.
        self.assertTrue(user_has_permission(self.member, self.alpha, "Product_View"))


class TestUserHasPermissionOr403(LegacyAuthorizationBaseTestCase):
    def test_raises_for_outsider(self):
        with self.assertRaises(PermissionDenied):
            user_has_permission_or_403(self.outsider, self.alpha, "view")

    def test_passes_for_member(self):
        # Should not raise.
        user_has_permission_or_403(self.member, self.alpha, "view")

    def test_passes_for_superuser(self):
        user_has_permission_or_403(self.superuser, self.beta, Permissions.Product_Delete)


class TestUserHasPermissionUnsupportedObject(LegacyAuthorizationBaseTestCase):

    """
    The legacy implementation raises NoAuthorizationImplementedError
    for object types it does not know how to gate.
    """

    def test_unknown_object_type(self):
        sentinel = object()  # not a known model
        with self.assertRaises(NoAuthorizationImplementedError):
            user_has_permission(self.member, sentinel, "view")


class TestUserHasGlobalPermissionLegacy(LegacyAuthorizationBaseTestCase):

    """
    Legacy global permissions reduce to is_superuser / is_staff with
    one configuration-permission carve-out for product_type creation.
    """

    def test_anonymous_denied(self):
        self.assertFalse(user_has_global_permission(None, "view"))

    def test_superuser_allowed(self):
        self.assertTrue(user_has_global_permission(self.superuser, "view"))
        self.assertTrue(user_has_global_permission(self.superuser, "delete"))

    def test_staff_allowed_general_actions(self):
        self.assertTrue(user_has_global_permission(self.staff, "view"))
        self.assertTrue(user_has_global_permission(self.staff, "edit"))

    def test_staff_denied_superuser_only(self):
        self.assertFalse(user_has_global_permission(self.staff, Action.SuperuserOnly))

    def test_outsider_denied(self):
        self.assertFalse(user_has_global_permission(self.outsider, "view"))

    def test_dojo_add_product_type_carveout(self):
        # Non-staff with django.add_product_type configuration permission
        # can globally add a product type — sole pre-2020 carve-out.
        with patch("dojo.authorization.authorization.user_has_configuration_permission", return_value=True):
            self.assertTrue(user_has_global_permission(self.outsider, "add"))


class TestUserHasConfigurationPermission(LegacyAuthorizationBaseTestCase):

    """
    Configuration permissions reduce to is_superuser / is_staff under
    legacy authorization, with Django's ``user.has_perm`` consulted as
    a fallback for explicit grants on non-staff users.
    """

    def test_anonymous_denied(self):
        self.assertFalse(user_has_configuration_permission(None, "dojo.add_product_type"))

    def test_user_with_perm(self):
        self.member.has_perm = Mock(return_value=True)
        self.assertTrue(user_has_configuration_permission(self.member, "dojo.add_product_type"))

    def test_user_without_perm(self):
        self.member.has_perm = Mock(return_value=False)
        self.assertFalse(user_has_configuration_permission(self.member, "dojo.add_product_type"))

    def test_staff_bypasses_without_django_perm(self):
        # is_staff is the legacy bypass for configuration permissions —
        # mirrors the pre-2020 behavior where staff was an absolute
        # bypass on every perm_type. has_perm is not consulted here.
        self.staff.has_perm = Mock(return_value=False)
        self.assertTrue(user_has_configuration_permission(self.staff, "auth.view_user"))
        self.assertTrue(user_has_configuration_permission(self.staff, "auth.delete_user"))
        self.assertTrue(user_has_configuration_permission(self.staff, "auth.view_group"))
        self.staff.has_perm.assert_not_called()

    def test_superuser_bypasses_without_django_perm(self):
        self.superuser.has_perm = Mock(return_value=False)
        self.assertTrue(user_has_configuration_permission(self.superuser, "auth.view_user"))
        self.superuser.has_perm.assert_not_called()


class TestRoleHelpersAreInertUnderLegacy(DojoTestCase):

    """
    The role-based helpers are stubs under legacy. They exist so
    transitional callers don't AttributeError; they don't raise.
    """

    def test_role_has_permission_returns_false(self):
        self.assertFalse(role_has_permission(Roles.Maintainer, Permissions.Product_Edit))
        self.assertFalse(role_has_permission(9999, Permissions.Product_Edit))  # bogus role: no exception

    def test_role_has_global_permission_returns_false(self):
        self.assertFalse(role_has_global_permission(Roles.Owner, Permissions.Product_Edit))

    def test_get_roles_for_permission_returns_empty(self):
        self.assertEqual(get_roles_for_permission(Permissions.Product_Edit), set())
        self.assertEqual(get_roles_for_permission(9999), set())  # bogus permission: no exception


class TestDojoGroupAuthorization(LegacyAuthorizationBaseTestCase):

    """Group / Group_Member access is staff-only under legacy."""

    def test_group_visible_to_staff(self):
        g = Dojo_Group.objects.create(name="auth_test_group")
        self.assertTrue(user_has_permission(self.staff, g, "view"))

    def test_group_invisible_to_non_staff(self):
        g = Dojo_Group.objects.create(name="auth_test_group_2")
        self.assertFalse(user_has_permission(self.member, g, "view"))
