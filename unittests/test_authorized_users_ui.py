"""
End-to-end tests for the new "Authorized Users" classic-UI flow on the
legacy authorization branch.

Covers:
* Adding via the form endpoint puts the user on
  Product.authorized_users / Product_Type.authorized_users and grants
  membership-based access via user_has_permission.
* Removing via the delete endpoint clears that membership.
* Non-staff users are 403 on both endpoints (Permissions.*_Manage_Members
  maps through permission_to_action() to Action.StaffOnly under legacy).
* The new panel renders the listed user on /product/<id>/ and /product/type/<id>/
  and the legacy Members panel header is gone (regression guard for the
  OS template strip).
"""
from django.urls import reverse

from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.models import Dojo_User, Product, Product_Type
from unittests.dojo_test_case import DojoTestCase


class AuthorizedUsersUIBaseTestCase(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.pt = Product_Type.objects.create(name="auth_ui_test_pt")
        cls.product = Product.objects.create(
            name="auth_ui_test_product",
            description="x",
            prod_type=cls.pt,
        )
        cls.admin = Dojo_User.objects.create(
            username="auth_ui_admin", is_staff=True,
        )
        cls.target = Dojo_User.objects.create(
            username="auth_ui_target", is_active=True,
        )
        cls.bystander = Dojo_User.objects.create(
            username="auth_ui_bystander", is_active=True,
        )


class TestProductAuthorizedUsersUI(AuthorizedUsersUIBaseTestCase):

    def test_add_authorized_user_grants_access(self):
        self.client.force_login(self.admin)
        url = reverse("add_product_authorized_users", args=(self.product.id,))
        response = self.client.post(url, {"users": [self.target.id]})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.product.authorized_users.filter(pk=self.target.id).exists())
        self.assertTrue(user_has_permission(self.target, self.product, Permissions.Product_View))

    def test_remove_authorized_user_revokes_access(self):
        self.product.authorized_users.add(self.target)
        self.assertTrue(user_has_permission(self.target, self.product, Permissions.Product_View))

        self.client.force_login(self.admin)
        url = reverse("delete_product_authorized_user", args=(self.product.id, self.target.id))
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(self.product.authorized_users.filter(pk=self.target.id).exists())
        self.assertFalse(user_has_permission(self.target, self.product, Permissions.Product_View))

    def test_non_staff_cannot_add(self):
        self.client.force_login(self.bystander)
        url = reverse("add_product_authorized_users", args=(self.product.id,))
        response = self.client.post(url, {"users": [self.target.id]})
        # PermissionDenied is routed through dojo.views.custom_unauthorized_view
        # (handler403) which renders the 403 template with status=400.
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.product.authorized_users.filter(pk=self.target.id).exists())

    def test_non_staff_cannot_remove(self):
        self.product.authorized_users.add(self.target)
        self.client.force_login(self.bystander)
        url = reverse("delete_product_authorized_user", args=(self.product.id, self.target.id))
        response = self.client.post(url)
        # PermissionDenied is routed through dojo.views.custom_unauthorized_view
        # (handler403) which renders the 403 template with status=400.
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.product.authorized_users.filter(pk=self.target.id).exists())

    def test_panel_renders_with_authorized_user_listed(self):
        self.product.authorized_users.add(self.target)
        self.client.force_login(self.admin)
        response = self.client.get(reverse("view_product", args=(self.product.id,)))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode("utf-8")
        self.assertIn("Authorized Users", body)
        self.assertIn(self.target.username, body)
        self.assertNotIn(">Members</h4>", body)
        self.assertNotIn(">Groups</h4>", body)

    def test_unauthorized_user_locked_out_of_detail(self):
        self.client.force_login(self.bystander)
        response = self.client.get(reverse("view_product", args=(self.product.id,)))
        # custom_unauthorized_view (handler403) renders with status=400.
        self.assertEqual(response.status_code, 400)

    def test_authorized_user_can_view_detail(self):
        self.product.authorized_users.add(self.target)
        self.client.force_login(self.target)
        response = self.client.get(reverse("view_product", args=(self.product.id,)))
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_user_does_not_see_product_in_list(self):
        self.client.force_login(self.bystander)
        response = self.client.get(reverse("product"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.product.name, response.content.decode("utf-8"))

    def test_authorized_user_sees_product_in_list(self):
        self.product.authorized_users.add(self.target)
        self.client.force_login(self.target)
        response = self.client.get(reverse("product"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.product.name, response.content.decode("utf-8"))


class TestProductTypeAuthorizedUsersUI(AuthorizedUsersUIBaseTestCase):

    def test_add_authorized_user_grants_access(self):
        self.client.force_login(self.admin)
        url = reverse("add_product_type_authorized_users", args=(self.pt.id,))
        response = self.client.post(url, {"users": [self.target.id]})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.pt.authorized_users.filter(pk=self.target.id).exists())
        self.assertTrue(user_has_permission(self.target, self.pt, Permissions.Product_Type_View))
        # cascade: membership on the product_type grants access to its products
        self.assertTrue(user_has_permission(self.target, self.product, Permissions.Product_View))

    def test_remove_authorized_user_revokes_access(self):
        self.pt.authorized_users.add(self.target)
        self.client.force_login(self.admin)
        url = reverse("delete_product_type_authorized_user", args=(self.pt.id, self.target.id))
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(self.pt.authorized_users.filter(pk=self.target.id).exists())
        self.assertFalse(user_has_permission(self.target, self.pt, Permissions.Product_Type_View))

    def test_non_staff_cannot_add(self):
        self.client.force_login(self.bystander)
        url = reverse("add_product_type_authorized_users", args=(self.pt.id,))
        response = self.client.post(url, {"users": [self.target.id]})
        # PermissionDenied is routed through dojo.views.custom_unauthorized_view
        # (handler403) which renders the 403 template with status=400.
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.pt.authorized_users.filter(pk=self.target.id).exists())

    def test_non_staff_cannot_remove(self):
        self.pt.authorized_users.add(self.target)
        self.client.force_login(self.bystander)
        url = reverse("delete_product_type_authorized_user", args=(self.pt.id, self.target.id))
        response = self.client.post(url)
        # PermissionDenied is routed through dojo.views.custom_unauthorized_view
        # (handler403) which renders the 403 template with status=400.
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.pt.authorized_users.filter(pk=self.target.id).exists())

    def test_panel_renders_with_authorized_user_listed(self):
        self.pt.authorized_users.add(self.target)
        self.client.force_login(self.admin)
        response = self.client.get(reverse("view_product_type", args=(self.pt.id,)))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode("utf-8")
        self.assertIn("Authorized Users", body)
        self.assertIn(self.target.username, body)
        self.assertNotIn(">Members</h4>", body)
        self.assertNotIn(">Groups</h4>", body)

    def test_unauthorized_user_locked_out_of_detail(self):
        self.client.force_login(self.bystander)
        response = self.client.get(reverse("view_product_type", args=(self.pt.id,)))
        self.assertEqual(response.status_code, 400)

    def test_authorized_user_can_view_detail(self):
        self.pt.authorized_users.add(self.target)
        self.client.force_login(self.target)
        response = self.client.get(reverse("view_product_type", args=(self.pt.id,)))
        self.assertEqual(response.status_code, 200)

    def test_authorized_user_sees_cascading_product_in_list(self):
        # cascade: membership on the product_type grants access to its products
        self.pt.authorized_users.add(self.target)
        self.client.force_login(self.target)
        response = self.client.get(reverse("product"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.product.name, response.content.decode("utf-8"))

    def test_unauthorized_user_does_not_see_product_type_in_list(self):
        self.client.force_login(self.bystander)
        response = self.client.get(reverse("product_type"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.pt.name, response.content.decode("utf-8"))
