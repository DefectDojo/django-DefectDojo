"""
The Tool Configuration edit page must not return stored credentials.

``dojo.change_tool_configuration`` lets a non-superuser edit the instance's tool
configurations. The page used to decrypt the stored password and ssh key and bind
all three credential fields into the rendered form, so the permission also handed
out every stored integration credential in cleartext.
"""

from django.contrib.auth.models import Permission
from django.test import Client
from django.urls import reverse

from dojo.models import Tool_Configuration, Tool_Type, User
from dojo.utils import dojo_crypto_encrypt, prepare_for_view

from .dojo_test_case import DojoTestCase, versioned_fixtures

PASSWORD = "stored-password-value"
SSH_KEY = "stored-ssh-key-value"
API_KEY = "stored-api-key-value"
URL = "https://scanner.example.com"
NEW_PASSWORD = "replacement-password-value"


@versioned_fixtures
class ToolConfigCredentialDisclosureTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        # A tool type outside SCAN_APIS, so saving does not attempt a connection.
        tool_type, _ = Tool_Type.objects.get_or_create(name="Disclosure Test Tool")
        self.tool_config = Tool_Configuration.objects.create(
            name="victim configuration",
            tool_type=tool_type,
            url=URL,
            authentication_type="Password",
            username="service-account",
            password=dojo_crypto_encrypt(PASSWORD),
            ssh=dojo_crypto_encrypt(SSH_KEY),
            api_key=API_KEY,
        )
        self.editor = User.objects.create(username="tool_config_editor")
        self.editor.user_permissions.add(
            Permission.objects.get(content_type__app_label="dojo", codename="change_tool_configuration"),
        )
        self.url = reverse("edit_tool_config", args=[self.tool_config.id])
        self.client = Client()
        self.client.force_login(self.editor)

    def _post(self, overrides):
        data = {
            "name": self.tool_config.name,
            "tool_type": self.tool_config.tool_type.id,
            "url": URL,
            "authentication_type": "Password",
            "username": "service-account",
            "password": "",
            "ssh": "",
            "api_key": "",
        }
        data.update(overrides)
        response = self.client.post(self.url, data)
        self.tool_config.refresh_from_db()
        return response

    def test_edit_page_does_not_return_the_stored_credentials(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.content[:300])
        for secret in (PASSWORD, SSH_KEY, API_KEY):
            self.assertNotIn(secret.encode(), response.content)

    def test_blank_credentials_keep_the_stored_values(self):
        self.assertEqual(self._post({"name": "renamed configuration"}).status_code, 302)
        self.assertEqual(self.tool_config.name, "renamed configuration")
        self.assertEqual(prepare_for_view(self.tool_config.password), PASSWORD)
        self.assertEqual(prepare_for_view(self.tool_config.ssh), SSH_KEY)
        self.assertEqual(self.tool_config.api_key, API_KEY)

    def test_a_submitted_credential_replaces_the_stored_one_and_is_encrypted(self):
        self.assertEqual(self._post({"password": NEW_PASSWORD}).status_code, 302)
        self.assertTrue(self.tool_config.password.startswith("AES."))
        self.assertEqual(prepare_for_view(self.tool_config.password), NEW_PASSWORD)
        # The fields left blank are still untouched.
        self.assertEqual(prepare_for_view(self.tool_config.ssh), SSH_KEY)

    def test_blank_credentials_are_not_reused_against_a_new_url(self):
        """
        An editor cannot read the credentials any more, so they must not be able to
        pair them with a destination of their own choosing either.
        """
        self.assertEqual(self._post({"url": "https://attacker.example.net"}).status_code, 302)
        self.assertNotEqual(prepare_for_view(self.tool_config.password), PASSWORD)
        self.assertNotEqual(prepare_for_view(self.tool_config.ssh), SSH_KEY)
        self.assertNotEqual(self.tool_config.api_key, API_KEY)
