from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import System_Settings, User
from dojo.system_settings.ui.forms import SystemSettingsForm

from .dojo_test_case import DojoTestCase, versioned_fixtures


def set_read_only_mode(value: bool) -> None:
    system_settings = System_Settings.objects.get(no_cache=True)
    system_settings.read_only_mode = value
    system_settings.save()


def admin_api_client() -> APIClient:
    token, _ = Token.objects.get_or_create(user=User.objects.get(username="admin"))
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    return client


@versioned_fixtures
class TestReadOnlyModeSetting(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.api = admin_api_client()

    def test_read_only_mode_defaults_off(self):
        self.assertFalse(System_Settings.objects.get(no_cache=True).read_only_mode)

    def test_form_shows_read_only_mode(self):
        self.assertIn("read_only_mode", SystemSettingsForm().fields)

    def test_api_patch_sets_read_only_mode(self):
        settings_id = System_Settings.objects.get(no_cache=True).id
        response = self.api.patch(f"/api/v2/system_settings/{settings_id}/", {"read_only_mode": True}, format="json")
        self.assertEqual(200, response.status_code, response.content)
        self.assertTrue(System_Settings.objects.get(no_cache=True).read_only_mode)
