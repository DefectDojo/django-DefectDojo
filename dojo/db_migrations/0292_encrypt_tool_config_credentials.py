import logging

from django.db import migrations

import dojo.db_utils

logger = logging.getLogger(__name__)

CREDENTIAL_COLUMNS = ("password", "ssh", "api_key")

# Read in bounded chunks so a large Tool_Configuration table never loads every
# row at once.
BATCH_SIZE = 500


def encrypt_plaintext_credentials(apps, schema_editor):
    """
    Encrypt the Tool_Configuration credentials that earlier releases stored in the clear.

    Only one write path ever encrypted, so most rows hold plaintext. Migration
    0272 could not pick them up because it only upgraded values already carrying
    the legacy "AES.1:" prefix.

    This reads the columns through a cursor rather than the model so it sees the
    stored bytes instead of the value EncryptedTextField decodes. Anything
    already prefixed is left alone, which also protects a value encrypted under
    a key this deployment no longer has from being overwritten.
    """
    from dojo.utils import dojo_crypto_encrypt

    connection = schema_editor.connection
    encrypted = 0
    last_id = 0
    while True:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, password, ssh, api_key FROM dojo_tool_configuration "
                "WHERE id > %s ORDER BY id LIMIT %s",
                [last_id, BATCH_SIZE],
            )
            page = cursor.fetchall()
        if not page:
            break
        last_id = page[-1][0]

        for row_id, *values in page:
            updates = {
                column: dojo_crypto_encrypt(value)
                for column, value in zip(CREDENTIAL_COLUMNS, values, strict=True)
                if value and not value.startswith(dojo.db_utils.ENCRYPTED_VALUE_PREFIXES)
            }
            if not updates:
                continue
            assignments = ", ".join(f"{column} = %s" for column in updates)
            with connection.cursor() as cursor:
                cursor.execute(
                    f"UPDATE dojo_tool_configuration SET {assignments} WHERE id = %s",
                    [*updates.values(), row_id],
                )
            encrypted += 1

    if encrypted:
        logger.info("Encrypted credentials for %d Tool_Configuration rows", encrypted)


def noop_reverse(apps, schema_editor):
    # Decrypting on the way back would put the credentials in the clear again,
    # which is the state this migration exists to leave.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("dojo", "0291_dojometa_location_product"),
    ]

    operations = [
        migrations.AlterField(
            model_name="tool_configuration",
            name="password",
            field=dojo.db_utils.EncryptedTextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="tool_configuration",
            name="ssh",
            field=dojo.db_utils.EncryptedTextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="tool_configuration",
            name="api_key",
            field=dojo.db_utils.EncryptedTextField(blank=True, null=True, verbose_name="API Key"),
        ),
        migrations.RunPython(encrypt_plaintext_credentials, noop_reverse),
    ]
