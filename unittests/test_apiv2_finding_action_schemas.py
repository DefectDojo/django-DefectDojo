import datetime

from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from drf_spectacular.settings import spectacular_settings
from rest_framework.test import APIClient, APITestCase

from dojo.models import (
    Dojo_User,
    DojoMeta,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)

METADATA_PATH = "/api/v2/findings/{id}/metadata/"
TAGS_PATH = "/api/v2/findings/{id}/tags/"


@override_settings(SECURE_SSL_REDIRECT=False)
class FindingActionSchemaTest(APITestCase):

    """
    The OpenAPI document must describe the finding metadata and tags actions as they behave.

    Regression: DELETE documented the ``name`` query parameter as an integer although it is the
    metadata name, PUT did not document the ``name`` query parameter it requires, and the tags
    POST documented 201 although the action answers 200. A generated client could not send a
    real metadata name and expected the wrong status.
    """

    @classmethod
    def setUpTestData(cls):
        generator = spectacular_settings.DEFAULT_GENERATOR_CLASS()
        cls.paths = generator.get_schema(request=None, public=True)["paths"]

        cls.user = Dojo_User.objects.create(username="finding-action-schema", is_superuser=True, is_staff=True)
        product_type = Product_Type.objects.create(name="finding-action-schema")
        product = Product.objects.create(name="finding-action-schema", description="Test", prod_type=product_type)
        start = timezone.now()
        engagement = Engagement.objects.create(
            name="finding-action-schema", product=product, target_start=start.date(), target_end=start.date(),
        )
        test_type = Test_Type.objects.create(name="finding-action-schema")
        test = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=start, target_end=start + datetime.timedelta(days=1),
        )
        cls.finding = Finding.objects.create(
            title="finding-action-schema", test=test, reporter=cls.user, severity="Info", numerical_severity="S4",
        )

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def name_parameter(self, method):
        parameters = {p["name"]: p for p in self.paths[METADATA_PATH][method].get("parameters", [])}
        self.assertIn("name", parameters, msg=f"{method.upper()} {METADATA_PATH} must document ?name=")
        return parameters["name"]

    def test_metadata_delete_documents_name_as_a_string(self):
        parameter = self.name_parameter("delete")
        self.assertEqual(parameter["in"], "query")
        self.assertTrue(parameter["required"])
        self.assertEqual(parameter["schema"]["type"], "string")

        DojoMeta.objects.create(finding=self.finding, name="env", value="prod")
        url = reverse("finding-metadata", args=(self.finding.id,))
        response = self.client.delete(url + "?name=env")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(DojoMeta.objects.filter(finding=self.finding, name="env").exists())

    def test_metadata_put_documents_the_required_name_query_parameter(self):
        parameter = self.name_parameter("put")
        self.assertEqual(parameter["in"], "query")
        self.assertTrue(parameter["required"])
        self.assertEqual(parameter["schema"]["type"], "string")

        DojoMeta.objects.create(finding=self.finding, name="env", value="prod")
        url = reverse("finding-metadata", args=(self.finding.id,))
        body = {"name": "env", "value": "staging"}
        self.assertEqual(self.client.put(url, body, format="json").status_code, 400)
        self.assertEqual(self.client.put(url + "?name=env", body, format="json").status_code, 200)
        self.assertEqual(DojoMeta.objects.get(finding=self.finding, name="env").value, "staging")
        # PUT upserts: a name with no entry creates one, as the parameter description says.
        self.assertIn("created", parameter["description"])
        created = self.client.put(url + "?name=absent", {"name": "absent", "value": "v"}, format="json")
        self.assertEqual(created.status_code, 200, created.content)
        self.assertTrue(DojoMeta.objects.filter(finding=self.finding, name="absent").exists())

    def test_metadata_get_and_post_document_no_name_parameter(self):
        for method in ("get", "post"):
            with self.subTest(method=method):
                names = [p["name"] for p in self.paths[METADATA_PATH][method].get("parameters", [])]
                self.assertNotIn("name", names)

    def test_tags_post_documents_the_200_it_returns(self):
        responses = self.paths[TAGS_PATH]["post"]["responses"]
        self.assertIn("200", responses)
        self.assertNotIn("201", responses)
        self.assertIn("400", responses)
        self.assertEqual(responses["200"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/Tag")

        url = reverse("finding-tags", args=(self.finding.id,))
        response = self.client.post(url, {"tags": ["schema-check"]}, format="json")
        self.assertEqual(response.status_code, 200, response.content)
        response = self.client.post(url, {"tags": "not-a-list"}, format="json")
        self.assertEqual(response.status_code, 400, response.content)
