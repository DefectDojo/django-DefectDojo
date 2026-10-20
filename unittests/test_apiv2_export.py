import json
import uuid

from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import System_Settings
from dojo.system_settings.ui.forms import SystemSettingsForm
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


def user_client(username):
    token = Token.objects.get(user__username=username)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    return client


def admin_client():
    return user_client("admin")


def ndjson_lines(response):
    return [json.loads(line) for line in b"".join(response.streaming_content).splitlines()]


@versioned_fixtures
class TestInstallId(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.client = admin_client()

    def test_install_id_is_a_persisted_uuid(self):
        first = System_Settings.objects.get(no_cache=True).install_id
        self.assertIsInstance(first, uuid.UUID)
        self.assertEqual(first, System_Settings.objects.get(no_cache=True).install_id)

    def test_api_cannot_change_install_id(self):
        settings_row = System_Settings.objects.get(no_cache=True)
        response = self.client.patch(
            f"/api/v2/system_settings/{settings_row.id}/", {"install_id": str(uuid.uuid4())}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:1000])
        self.assertEqual(settings_row.install_id, System_Settings.objects.get(no_cache=True).install_id)
        self.assertEqual(str(settings_row.install_id), response.json()["install_id"])

    def test_form_has_no_install_id(self):
        self.assertNotIn("install_id", SystemSettingsForm().fields)
