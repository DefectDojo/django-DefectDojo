"""
An unrecognised permission must deny, not fall back to view access.

``permission_to_action()`` maps three input shapes onto the legacy ``Action``
vocabulary: an ``Action``, an action string ("view", "edit", ...), and a
``Permissions`` enum member or its name ("Product_Edit"). Anything it cannot
place used to return ``Action.View`` -- the most permissive action in the model
-- so an unresolved intent became read access instead of a refusal. Two ways
that reached the REST API:

  * ``check_object_permission()`` only takes a POST permission if the
    permission class passes one, and most pass three permissions, not four.
    A detail-route POST action inheriting such a class authorized as a plain
    View. (``UserHasRiskAcceptancePermission`` names all four precisely
    because ``expire`` / ``reinstate`` reach it that way.)
  * a permission whose name does not follow the ``<Noun>_<Verb>`` convention
    the suffix table expects -- ``Product_Manage`` rather than
    ``Product_Manage_Members`` -- silently downgraded from administrative to
    View.

Neither was reachable as a live privilege escalation on the routes that exist
today, which is exactly why it needed pinning down: the mapping was one new
``@action(detail=True, methods=["post"])`` away from granting one. These tests
hold the layer fail-closed, and assert the mapping still resolves every input
the codebase actually uses, so a future permission cannot silently land in the
unmapped bucket either.
"""
import datetime
from unittest.mock import Mock

from django.utils import timezone

from dojo.authorization import api_permissions as api_perms
from dojo.authorization.api_permissions import (
    BaseRelatedObjectPermission,
    check_object_permission,
)
from dojo.authorization.authorization import (
    user_has_global_permission,
    user_has_permission,
)
from dojo.authorization.roles_permissions import (
    Action,
    Permissions,
    permission_to_action,
)
from dojo.finding.queries import get_authorized_findings
from dojo.finding_group.queries import get_authorized_finding_groups
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from unittests.dojo_test_case import DojoTestCase

# Stand-ins for the ways an unresolvable permission reaches the mapper: the
# default check_object_permission() leaves in place, a typo, a name that misses
# the suffix table, and a value of the wrong type entirely.
UNMAPPED_PERMISSIONS = [
    None,
    "",
    "bogus",
    "Nonexistent_Permission",
    "Product_Frobnicate",
    0,
    object(),
]


class TestPermissionToActionFailsClosed(DojoTestCase):

    """permission_to_action() denies what it cannot map."""

    def test_unmapped_inputs_map_to_deny(self):
        for permission in UNMAPPED_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertEqual(Action.Deny, permission_to_action(permission))

    def test_none_does_not_map_to_view(self):
        # The specific regression: check_object_permission()'s default POST
        # permission is None, which used to resolve to Action.View.
        self.assertNotEqual(Action.View, permission_to_action(None))

    def test_every_permissions_member_still_resolves(self):
        # Guards the other direction: the suffix table must keep covering the
        # whole enum, or a real permission would start denying.
        unresolved = [p.name for p in Permissions if permission_to_action(p) == Action.Deny]
        self.assertEqual([], unresolved)

    def test_action_members_pass_through(self):
        for action in Action:
            with self.subTest(action=action):
                self.assertEqual(action, permission_to_action(action))

    def test_supported_input_shapes_are_unaffected(self):
        self.assertEqual(Action.View, permission_to_action("view"))
        self.assertEqual(Action.Edit, permission_to_action("edit"))
        self.assertEqual(Action.Delete, permission_to_action("delete"))
        self.assertEqual(Action.Add, permission_to_action("add"))
        self.assertEqual(Action.Import, permission_to_action("import"))
        self.assertEqual(Action.View, permission_to_action(Permissions.Product_View))
        self.assertEqual(Action.Edit, permission_to_action("Product_Edit"))
        self.assertEqual(Action.Import, permission_to_action(Permissions.Import_Scan_Result))
        self.assertEqual(Action.Edit, permission_to_action(Permissions.Risk_Acceptance))

    def test_manage_suffix_is_administrative(self):
        # "_Manage_" only matched with a trailing underscore, so a name ending
        # in _Manage fell through to View. Administrative names belong in the
        # staff-only bucket however they terminate.
        self.assertEqual(Action.StaffOnly, permission_to_action("Product_Manage"))
        self.assertEqual(Action.StaffOnly, permission_to_action("Product_Manage_Members"))
        self.assertEqual(Action.StaffOnly, permission_to_action(Permissions.Product_Manage_Members))
        self.assertEqual(Action.StaffOnly, permission_to_action(Permissions.Group_Add_Owner))


class UnmappedPermissionFixtureMixin:

    """
    A product with a member, plus staff, outsider and superuser accounts, and a
    finding hierarchy underneath so the queryset filters have rows to return.

    Deliberately no Endpoint: that model raises when V3_FEATURE_LOCATIONS is on,
    and the filters exercised here reach the same helpers via the finding chain.
    """

    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name="unmapped_perm_pt")
        cls.product = Product.objects.create(
            name="unmapped_perm_product", description="x", prod_type=cls.product_type,
        )

        cls.member = Dojo_User.objects.create(username="unmapped_perm_member")
        cls.outsider = Dojo_User.objects.create(username="unmapped_perm_outsider")
        cls.staff = Dojo_User.objects.create(username="unmapped_perm_staff", is_staff=True)
        cls.superuser = Dojo_User.objects.create(username="unmapped_perm_superuser", is_superuser=True)

        cls.product.authorized_users.add(cls.member)

        cls.engagement = Engagement.objects.create(
            product=cls.product, name="unmapped_perm_eng",
            target_start=datetime.date.today(), target_end=datetime.date.today(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Manual Test")
        cls.test = Test.objects.create(
            engagement=cls.engagement, test_type=test_type,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        cls.finding = Finding.objects.create(
            test=cls.test, title="unmapped_perm_finding", reporter=cls.member,
            severity="High", description="x", mitigation="x", impact="x",
        )
        cls.finding_group = Finding_Group.objects.create(
            test=cls.test, name="unmapped_perm_group", creator=cls.member,
        )


class TestUserHasPermissionDeniesUnmapped(UnmappedPermissionFixtureMixin, DojoTestCase):

    """user_has_permission() refuses an unresolvable permission."""

    def test_member_denied_for_unmapped_permission(self):
        for permission in UNMAPPED_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertFalse(user_has_permission(self.member, self.product, permission))

    def test_staff_denied_for_unmapped_permission(self):
        # is_staff is an absolute bypass for every *mapped* action in the legacy
        # model. It must not also carry an intent the layer could not resolve.
        for permission in UNMAPPED_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertFalse(user_has_permission(self.staff, self.product, permission))

    def test_outsider_denied_for_unmapped_permission(self):
        self.assertFalse(user_has_permission(self.outsider, self.product, None))

    def test_superuser_still_bypasses(self):
        # Documented and deliberate: the superuser bypass is resolved before the
        # permission is mapped at all, matching every other action.
        self.assertTrue(user_has_permission(self.superuser, self.product, None))

    def test_mapped_permissions_unaffected(self):
        self.assertTrue(user_has_permission(self.member, self.product, "view"))
        self.assertTrue(user_has_permission(self.member, self.product, "edit"))
        self.assertTrue(user_has_permission(self.staff, self.product, "view"))
        self.assertFalse(user_has_permission(self.outsider, self.product, "view"))

    def test_global_permission_denies_unmapped(self):
        for permission in UNMAPPED_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertFalse(user_has_global_permission(self.staff, permission))

    def test_global_permission_mapped_unaffected(self):
        self.assertTrue(user_has_global_permission(self.staff, "add"))
        self.assertFalse(user_has_global_permission(self.outsider, "add"))


class TestCheckObjectPermissionPost(UnmappedPermissionFixtureMixin, DojoTestCase):

    """check_object_permission() denies POST unless the class names a POST permission."""

    def _request(self, method, user):
        return Mock(method=method, user=user)

    def test_post_denied_when_post_permission_omitted(self):
        # The three-permission call shape used by most permission classes.
        for user in (self.member, self.staff, self.outsider):
            with self.subTest(user=user.username):
                self.assertFalse(
                    check_object_permission(
                        self._request("POST", user), self.product, "view", "edit", "delete",
                    ),
                )

    def test_post_allowed_when_post_permission_named(self):
        self.assertTrue(
            check_object_permission(
                self._request("POST", self.member), self.product, "view", "edit", "delete", "edit",
            ),
        )

    def test_post_still_enforces_the_named_permission(self):
        # Naming a permission is not the same as granting one.
        self.assertFalse(
            check_object_permission(
                self._request("POST", self.outsider), self.product, "view", "edit", "delete", "edit",
            ),
        )

    def test_other_methods_unaffected(self):
        self.assertTrue(
            check_object_permission(
                self._request("GET", self.member), self.product, "view", "edit", "delete",
            ),
        )
        self.assertTrue(
            check_object_permission(
                self._request("PATCH", self.member), self.product, "view", "edit", "delete",
            ),
        )
        self.assertFalse(
            check_object_permission(
                self._request("DELETE", self.member), self.product, "view", "edit", "delete",
            ),
        )

    def test_unhandled_method_denied(self):
        self.assertFalse(
            check_object_permission(
                self._request("OPTIONS", self.superuser), self.product, "view", "edit", "delete",
            ),
        )


class TestRelatedObjectPermissionMapsAreComplete(DojoTestCase):

    """
    Every BaseRelatedObjectPermission subclass names all four permissions.

    The base class defaults all four to None, so a subclass that omits one
    denies that method outright. That is the safe direction, but it is a silent
    way to lose a route, and for POST it was the path that used to resolve to
    View. Assert the maps are complete and that each entry resolves.
    """

    def test_all_subclasses_name_four_resolvable_permissions(self):
        expected_keys = {"get_permission", "put_permission", "delete_permission", "post_permission"}
        subclasses = [
            candidate
            for candidate in vars(api_perms).values()
            if isinstance(candidate, type)
            and issubclass(candidate, BaseRelatedObjectPermission)
            and candidate is not BaseRelatedObjectPermission
        ]
        self.assertNotEqual([], subclasses, "no related-object permission classes were discovered")

        for cls in subclasses:
            with self.subTest(permission_class=cls.__name__):
                self.assertEqual(expected_keys, set(cls.permission_map))
                for key, permission in cls.permission_map.items():
                    self.assertIsNotNone(permission, f"{cls.__name__}.{key} is unset")
                    self.assertNotEqual(
                        Action.Deny,
                        permission_to_action(permission),
                        f"{cls.__name__}.{key} does not resolve to an action",
                    )


class TestAuthorizedQuerysetsDenyUnmapped(UnmappedPermissionFixtureMixin, DojoTestCase):

    """The queryset filters do not hand out rows for an unresolvable permission."""

    def test_finding_groups_empty_for_unmapped_permission(self):
        # Routes through _filter_by_authorized_products, which short-circuits.
        for user in (self.member, self.staff, self.outsider):
            with self.subTest(user=user.username):
                self.assertEqual(0, get_authorized_finding_groups(None, user=user).count())

    def test_finding_groups_returned_for_mapped_permission(self):
        self.assertIn(self.finding_group, get_authorized_finding_groups("view", user=self.member))
        self.assertIn(self.finding_group, get_authorized_finding_groups("view", user=self.staff))
        self.assertNotIn(self.finding_group, get_authorized_finding_groups("view", user=self.outsider))

    def test_findings_returned_for_mapped_permission(self):
        self.assertIn(self.finding, get_authorized_findings("view", user=self.member))
        self.assertIn(self.finding, get_authorized_findings("view", user=self.staff))
        self.assertNotIn(self.finding, get_authorized_findings("view", user=self.outsider))

    def test_staff_loses_the_unrestricted_bypass_for_unmapped_permission(self):
        # get_authorized_findings() has its own _is_unrestricted() call rather
        # than going through the shared helper; staff must not get the whole
        # table there either.
        self.assertEqual(0, get_authorized_findings(None, user=self.staff).count())
