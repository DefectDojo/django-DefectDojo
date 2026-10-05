import uuid

from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo import __version__
from dojo.location.feature import locations_enabled
from dojo.models import System_Settings
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


class InstanceIdTest(DojoTestCase):
    def test_instance_id_is_a_stable_uuid(self):
        first = System_Settings.objects.get().instance_id
        self.assertIsInstance(first, uuid.UUID)

        row = System_Settings.objects.get(no_cache=True)
        row.save()

        self.assertEqual(System_Settings.objects.get().instance_id, first)


def token_client(username):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get(user__username=username).key)
    return client


@versioned_fixtures
class ExportManifestBasicsTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_manifest_rejects_anonymous_requests(self):
        response = APIClient().get(reverse("export-manifest"))
        self.assertIn(response.status_code, {401, 403})

    def test_manifest_rejects_non_superusers(self):
        response = token_client("user1").get(reverse("export-manifest"))
        self.assertEqual(response.status_code, 403, response.content[:500])

    def test_manifest_reports_version_and_instance(self):
        response = token_client("admin").get(reverse("export-manifest"))
        self.assertEqual(response.status_code, 200, response.content[:500])
        body = response.json()
        self.assertEqual(body["export_api_version"], 1)
        self.assertEqual(body["defectdojo_version"], __version__)
        self.assertEqual(body["instance_id"], str(System_Settings.objects.get().instance_id))
        self.assertEqual(body["locations_enabled"], locations_enabled())
        self.assertEqual(response["X-DefectDojo-Export-Version"], "1")

    def test_manifest_rejects_a_bad_file_cap(self):
        response = token_client("admin").get(reverse("export-manifest"), {"max_file_bytes": "lots"})
        self.assertEqual(response.status_code, 400)
