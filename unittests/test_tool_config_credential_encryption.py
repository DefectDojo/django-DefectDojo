"""
Regression test: Tool_Configuration credentials must be encrypted at rest no
matter which path wrote them.

Encryption used to live in the edit view, so the create views, the REST
serializer, the admin and ``loaddata`` all stored the credential in the clear,
and ``api_key`` was never encrypted by any path at all. The checks below read
the columns through a cursor, because the model field decrypts on the way out
and would hide the very thing under test.
"""
from django.db import connection

from dojo.models import Tool_Configuration, Tool_Type
from dojo.tool_config.api.serializer import ToolConfigurationSerializer
from dojo.tool_config.ui.forms import ToolConfigForm
from dojo.utils import dojo_crypto_encrypt

from .dojo_test_case import DojoTestCase

CREDENTIALS = {
    "password": "pw-plaintext-canary",
    "ssh": "ssh-plaintext-canary",
    "api_key": "apikey-plaintext-canary",
}


def stored_values(pk):
    """The credential columns exactly as Postgres holds them."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT password, ssh, api_key FROM dojo_tool_configuration WHERE id = %s", [pk],
        )
        return dict(zip(CREDENTIALS, cursor.fetchone(), strict=True))


class ToolConfigCredentialEncryptionTest(DojoTestCase):
    def setUp(self):
        self.tool_type, _ = Tool_Type.objects.get_or_create(name="SonarQube")

    def assert_encrypted_at_rest(self, tool_config):
        stored = stored_values(tool_config.pk)
        for field, plaintext in CREDENTIALS.items():
            with self.subTest(field=field):
                self.assertTrue(stored[field].startswith("AES.2:"), stored[field])
                self.assertNotIn(plaintext, stored[field])
        # and the application still sees the original value
        fresh = Tool_Configuration.objects.get(pk=tool_config.pk)
        for field, plaintext in CREDENTIALS.items():
            self.assertEqual(plaintext, getattr(fresh, field))

    def test_model_create_encrypts(self):
        # Covers every writer that goes through the ORM, including the admin and loaddata.
        self.assert_encrypted_at_rest(Tool_Configuration.objects.create(
            name="via-model", tool_type=self.tool_type, authentication_type="API", **CREDENTIALS,
        ))

    def test_serializer_create_encrypts(self):
        serializer = ToolConfigurationSerializer(data={
            "name": "via-api", "tool_type": self.tool_type.pk, "authentication_type": "API",
            **CREDENTIALS,
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assert_encrypted_at_rest(serializer.save())

    def test_serializer_update_encrypts(self):
        tool_config = Tool_Configuration.objects.create(
            name="via-api-update", tool_type=self.tool_type, authentication_type="API",
        )
        serializer = ToolConfigurationSerializer(tool_config, data=CREDENTIALS, partial=True)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assert_encrypted_at_rest(serializer.save())

    def test_form_create_encrypts(self):
        form = ToolConfigForm(data={
            "name": "via-form", "tool_type": self.tool_type.pk, "authentication_type": "API",
            "url": "https://example.invalid", **CREDENTIALS,
        })
        self.assertTrue(form.is_valid(), form.errors)
        self.assert_encrypted_at_rest(form.save())

    def test_queryset_update_encrypts(self):
        tool_config = Tool_Configuration.objects.create(
            name="via-queryset", tool_type=self.tool_type, authentication_type="API",
        )
        Tool_Configuration.objects.filter(pk=tool_config.pk).update(**CREDENTIALS)
        self.assert_encrypted_at_rest(tool_config)

    def test_existing_plaintext_row_is_readable_and_encrypted_on_save(self):
        # Rows written before this change hold plaintext. They must keep working,
        # not decode to "" the way the old edit view made them.
        tool_config = Tool_Configuration.objects.create(
            name="legacy-plaintext", tool_type=self.tool_type, authentication_type="API",
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE dojo_tool_configuration SET password = %s, ssh = %s, api_key = %s "
                "WHERE id = %s",
                [*CREDENTIALS.values(), tool_config.pk],
            )

        legacy = Tool_Configuration.objects.get(pk=tool_config.pk)
        for field, plaintext in CREDENTIALS.items():
            self.assertEqual(plaintext, getattr(legacy, field))

        legacy.save()
        self.assert_encrypted_at_rest(legacy)

    def test_an_already_encrypted_value_is_stored_as_is(self):
        # A caller that hands over ciphertext (a fixture, or code that encrypted
        # for itself) must not have it encrypted a second time and become
        # undecryptable.
        ciphertext = dojo_crypto_encrypt(CREDENTIALS["password"])
        tool_config = Tool_Configuration.objects.create(
            name="pre-encrypted", tool_type=self.tool_type, authentication_type="API",
            password=ciphertext,
        )
        self.assertEqual(ciphertext, stored_values(tool_config.pk)["password"])
        self.assertEqual(
            CREDENTIALS["password"],
            Tool_Configuration.objects.get(pk=tool_config.pk).password,
        )
