from django.forms import modelform_factory
from django.test import override_settings
from rest_framework.test import APITestCase

from dojo.models import Dojo_User, Product_Lifecycle, Product_Origin, Product_Platform
from dojo.product_attributes.models import VALUE_COMMA_ERROR
from dojo.product_attributes.ui.forms import ProductLifecycleForm, ProductOriginForm, ProductPlatformForm

ENDPOINTS = (
    ("product_platforms", Product_Platform, ProductPlatformForm),
    ("product_lifecycles", Product_Lifecycle, ProductLifecycleForm),
    ("product_origins", Product_Origin, ProductOriginForm),
)


@override_settings(SECURE_SSL_REDIRECT=False)
class TestProductAttributeValueComma(APITestCase):

    """
    Regression: an Asset attribute option's value could contain a comma, but the findings filters over
    these values (product_lifecycle on /api/v2/findings/) take a comma list and split on it, so such an
    option could never be matched. Creating one is refused; a row that already has one stays editable.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="attr_comma_admin", is_staff=True, is_superuser=True)

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def test_api_create_refuses_a_comma_in_value(self):
        for endpoint, model, _form in ENDPOINTS:
            for value, accepted in (("web, mobile", False), ("web,", False), ("web and mobile", True)):
                with self.subTest(endpoint=endpoint, value=value):
                    response = self.client.post(
                        f"/api/v2/{endpoint}/", data={"value": value, "name": "Web and Mobile"}, format="json",
                    )
                    persisted = list(model.objects.filter(value=value).values_list("value", flat=True))
                    if accepted:
                        self.assertEqual(response.status_code, 201, response.content[:500])
                        self.assertEqual(persisted, [value], f"persisted={persisted}")
                    else:
                        self.assertEqual(response.status_code, 400, response.content[:500])
                        self.assertEqual(response.json()["value"], [VALUE_COMMA_ERROR], response.content[:500])
                        self.assertEqual(persisted, [], f"persisted={persisted}")

    def test_api_update_of_a_legacy_comma_value_still_saves(self):
        for endpoint, model, _form in ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                option = model.objects.create(value="legacy, comma", name="Legacy")
                response = self.client.put(
                    f"/api/v2/{endpoint}/{option.id}/",
                    data={"value": "legacy, comma", "name": "Legacy Renamed"}, format="json",
                )
                self.assertEqual(response.status_code, 200, response.content[:500])
                option.refresh_from_db()
                self.assertEqual((option.value, option.name), ("legacy, comma", "Legacy Renamed"))

    def test_create_form_refuses_a_comma_in_value(self):
        for _endpoint, model, form_class in ENDPOINTS:
            for value, accepted in (("web, mobile", False), ("web and mobile", True)):
                with self.subTest(model=model.__name__, value=value):
                    form = form_class(data={"value": value, "name": "Web and Mobile", "icon": "", "display_order": 0})
                    self.assertEqual(form.is_valid(), accepted, form.errors)
                    if not accepted:
                        self.assertEqual(form.errors, {"value": [VALUE_COMMA_ERROR]})

    def test_edit_form_keeps_a_legacy_comma_value(self):
        for _endpoint, model, form_class in ENDPOINTS:
            with self.subTest(model=model.__name__):
                option = model.objects.create(value="legacy, comma", name="Legacy")
                form = form_class(
                    data={"value": "legacy, comma", "name": "Legacy Renamed", "icon": "", "display_order": 0},
                    instance=option,
                )
                self.assertTrue(form.is_valid(), form.errors)
                form.save()
                option.refresh_from_db()
                self.assertEqual((option.value, option.name), ("legacy, comma", "Legacy Renamed"))

    def test_default_model_form_refuses_a_comma_in_value(self):
        # Django admin builds this form for the registered models; the check lives on the model, so it applies there too.
        for _endpoint, model, _form in ENDPOINTS:
            form_class = modelform_factory(model, fields="__all__")
            with self.subTest(model=model.__name__):
                form = form_class(data={"value": "web, mobile", "name": "Web and Mobile", "icon": "", "display_order": 0})
                self.assertFalse(form.is_valid())
                self.assertEqual(form.errors, {"value": [VALUE_COMMA_ERROR]})
                legacy = model.objects.create(value="legacy, admin", name="Legacy")
                form = form_class(
                    data={"value": "legacy, admin", "name": "Legacy Renamed", "icon": "", "display_order": 0},
                    instance=legacy,
                )
                self.assertTrue(form.is_valid(), form.errors)
