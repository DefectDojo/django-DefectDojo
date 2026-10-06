import datetime

from django.urls import reverse

from dojo.location.feature import locations_enabled
from dojo.models import (
    Dojo_User,
    Endpoint,
    Engagement,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Test,
    Test_Type,
    Tool_Configuration,
    Tool_Type,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class ImportFormChoicesTest(DojoTestCase):

    """The import and re-import pages offer the user's own endpoints and the product's API scan configurations."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        product_type = Product_Type.objects.create(name="import form choices")
        self.product = Product.objects.create(name="import form empty product", prod_type=product_type, description="x")
        self.member = Dojo_User.objects.create(username="import-form-member")
        self.product.authorized_users.add(self.member)
        self.client.force_login(self.member)
        self.other_product = Product.objects.create(name="import form other product", prod_type=product_type, description="x")
        self.engagement = Engagement.objects.create(
            name="import form engagement", product=self.product,
            target_start=datetime.date(2026, 1, 1), target_end=datetime.date(2026, 2, 1),
        )
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=Test_Type.objects.get_or_create(name="ZAP Scan")[0],
            scan_type="ZAP Scan",
            target_start=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2026, 2, 1, tzinfo=datetime.UTC),
        )

        tool_type, _ = Tool_Type.objects.get_or_create(name="import form tool type")
        tool_configuration = Tool_Configuration.objects.create(name="import form tool", tool_type=tool_type)
        self.other_scan_configuration = Product_API_Scan_Configuration.objects.create(
            product=self.other_product, tool_configuration=tool_configuration,
        )
        if locations_enabled():
            self.other_endpoint = URL.create_location_from_value("https://import-form-other.example.test/").location
            self.other_endpoint.associate_with_product(self.other_product)
        else:
            self.other_endpoint = Endpoint.objects.create(host="import-form-other.example.test", product=self.other_product)

    def _assert_scoped(self, form):
        self.assertNotIn(self.other_endpoint.pk, form.fields["endpoints"].queryset.values_list("pk", flat=True))
        self.assertNotIn(
            self.other_scan_configuration.pk,
            form.fields["api_scan_configuration"].queryset.values_list("pk", flat=True),
        )

    def test_import_form_choices(self):
        response = self.client.get(reverse("import_scan_results", args=(self.engagement.id,)))
        self.assertEqual(200, response.status_code)
        self._assert_scoped(response.context["form"])

    def test_reimport_form_choices(self):
        response = self.client.get(reverse("re_import_scan_results", args=(self.test.id,)))
        self.assertEqual(200, response.status_code)
        self._assert_scoped(response.context["form"])
