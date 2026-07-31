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
"""
from types import SimpleNamespace

from rest_framework.exceptions import PermissionDenied

from dojo.models import Dojo_User, Tool_Configuration, Tool_Type
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
