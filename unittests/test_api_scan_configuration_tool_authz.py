"""
Regression test: the "Add API Scan Configuration" form and its REST serializer
must not offer or accept a Tool_Configuration the requesting user is not
authorized to view.

Selecting a tool configuration drives an authenticated request with the
credential stored on it, so the choice is gated by the same
``view_tool_configuration`` configuration permission that guards the
tool-configuration views. A user without that permission gets an empty choice
set, and a submitted pk is rejected, so narrowing the rendered <select> alone
cannot be bypassed by POSTing the id directly, and the REST endpoint cannot be
used to attach an unauthorized configuration either.

The V3 asset alias is a second serializer over the same model, so it is covered
here too: a member of the asset who lacks the permission cannot attach an
unauthorized configuration through the alias, on create or on update.
"""
from types import SimpleNamespace

from crum import impersonate
from rest_framework.exceptions import PermissionDenied

from dojo.asset.api.serializers import AssetAPIScanConfigurationSerializer
from dojo.models import Dojo_User, Product_API_Scan_Configuration, Tool_Configuration, Tool_Type
from dojo.product.api.serializer import ProductAPIScanConfigurationSerializer
from dojo.product.ui.forms import Product_API_Scan_ConfigurationForm

from .dojo_test_case import DojoTestCase


class ApiScanConfigurationToolAuthzTest(DojoTestCase):
    def setUp(self):
        tool_type, _ = Tool_Type.objects.get_or_create(name="SonarQube")
        self.tool_config = Tool_Configuration.objects.create(
            name="prod-sonarqube", tool_type=tool_type, authentication_type="API",
            url="http://example.invalid/api", api_key="ADMIN-TOKEN",
        )
        self.other_tool_config = Tool_Configuration.objects.create(
            name="prod-sonarqube-secondary", tool_type=tool_type, authentication_type="API",
            url="http://example.invalid/api2", api_key="ADMIN-TOKEN-2",
        )
        self.unprivileged = Dojo_User.objects.create(
            username="scanconf_unprivileged", is_staff=False, is_superuser=False,
        )
        self.staff = Dojo_User.objects.create(
            username="scanconf_staff", is_staff=True, is_superuser=False,
        )
        self.product_type = self.create_product_type("scanconf-org")

    def _post(self, user):
        return Product_API_Scan_ConfigurationForm(
            {"tool_configuration": self.tool_config.pk, "service_key_1": "k1"},
            user=user,
        )

    def test_unprivileged_user_is_offered_no_tool_configurations(self):
        form = Product_API_Scan_ConfigurationForm(user=self.unprivileged)
        self.assertNotIn(self.tool_config, form.fields["tool_configuration"].queryset)

    def test_unprivileged_user_cannot_submit_a_tool_configuration(self):
        form = self._post(self.unprivileged)
        self.assertFalse(form.is_valid())
        self.assertIn("tool_configuration", form.errors)

    def test_privileged_user_can_select_the_tool_configuration(self):
        form = self._post(self.staff)
        self.assertIn(self.tool_config, form.fields["tool_configuration"].queryset)
        self.assertNotIn("tool_configuration", form.errors)

    def _serializer(self, user):
        product = self.create_product("scanconf-product", prod_type=self.product_type)
        return ProductAPIScanConfigurationSerializer(
            data={"product": product.pk, "tool_configuration": self.tool_config.pk, "service_key_1": "k1"},
            context={"request": SimpleNamespace(user=user)},
        )

    def test_rest_rejects_unauthorized_tool_configuration(self):
        serializer = self._serializer(self.unprivileged)
        with self.assertRaises(PermissionDenied):
            serializer.is_valid(raise_exception=True)

    def test_rest_allows_authorized_tool_configuration(self):
        serializer = self._serializer(self.staff)
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def _asset_for(self, user, name):
        product = self.create_product(name, prod_type=self.product_type)
        product.authorized_users.add(user)
        return product

    def _alias_serializer(self, user, product, **kwargs):
        return AssetAPIScanConfigurationSerializer(
            data={"asset": product.pk, "tool_configuration": self.tool_config.pk, "service_key_1": "k1"},
            context={"request": SimpleNamespace(user=user)},
            **kwargs,
        )

    def test_alias_rest_rejects_unauthorized_tool_configuration(self):
        product = self._asset_for(self.unprivileged, "scanconf-alias-unprivileged")
        with impersonate(self.unprivileged), self.assertRaises(PermissionDenied):
            self._alias_serializer(self.unprivileged, product).is_valid(raise_exception=True)

    def test_alias_rest_rejects_unauthorized_tool_configuration_on_update(self):
        product = self._asset_for(self.unprivileged, "scanconf-alias-unprivileged-update")
        existing = Product_API_Scan_Configuration.objects.create(
            product=product, tool_configuration=self.other_tool_config, service_key_1="k0",
        )
        with impersonate(self.unprivileged), self.assertRaises(PermissionDenied):
            self._alias_serializer(
                self.unprivileged, product, instance=existing, partial=True,
            ).is_valid(raise_exception=True)

    def test_alias_rest_allows_authorized_tool_configuration(self):
        product = self._asset_for(self.staff, "scanconf-alias-staff")
        with impersonate(self.staff):
            serializer = self._alias_serializer(self.staff, product)
            self.assertTrue(serializer.is_valid(), serializer.errors)
