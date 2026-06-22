import logging

from django.db import migrations

logger = logging.getLogger(__name__)

# Tool_Configuration fields that hold credentials encrypted via
# dojo_crypto_encrypt()/prepare_for_view(). Each is re-encrypted from the legacy
# "AES.1" (AES-256-OFB) scheme to the modern "AES.2" (AES-256-GCM) scheme.
ENCRYPTED_FIELDS = ("password", "ssh", "api_key")

# Legacy stored-format prefix written by the old prepare_for_save().
LEGACY_PREFIX = "AES.1:"

# Re-encrypt in bounded chunks so a large Tool_Configuration table never loads
# every row into memory at once.
BATCH_SIZE = 500


def reencrypt_tool_config_credentials(apps, schema_editor):
    """
    Eagerly upgrade every stored Tool_Configuration credential from the legacy
    "AES.1" (AES-256-OFB) format to the modern "AES.2" (AES-256-GCM) format.

    prepare_for_view() already reads both formats, so values would otherwise
    upgrade only lazily the next time a Tool Config is saved. This migration
    performs the transition proactively so the legacy OFB decrypt path can
    eventually be removed once no "AES.1" values remain. See the "REMOVAL
    TRACKING (legacy OFB path)" note in dojo/utils.py for the conditions under
    which that legacy code (encrypt/decrypt/prepare_for_save and the OFB import)
    can be deleted.

    Both schemes reuse the same key from get_db_key(); no key rotation or
    settings change is involved. A value that fails to decrypt (e.g. produced
    with a different key) is left untouched rather than clobbered.
    """
    # Imported here, not at module load, so the migration graph can be built
    # without pulling in the full dojo.utils runtime/settings dependencies.
    from dojo.utils import dojo_crypto_encrypt, prepare_for_view

    Tool_Configuration = apps.get_model("dojo", "Tool_Configuration")

    upgraded = 0
    last_id = 0
    while True:
        page = list(
            Tool_Configuration.objects.filter(id__gt=last_id)
            .order_by("id")
            .values("id", *ENCRYPTED_FIELDS)[:BATCH_SIZE],
        )
        if not page:
            break
        last_id = page[-1]["id"]

        for row in page:
            updates = {}
            for field in ENCRYPTED_FIELDS:
                value = row[field]
                if not value or not value.startswith(LEGACY_PREFIX):
                    continue
                decrypted = prepare_for_view(value)
                if not decrypted:
                    # Decryption failed (wrong key / tampered value). Leave the
                    # stored value as-is instead of overwriting it with junk.
                    logger.warning(
                        "Skipping Tool_Configuration %s field %r: legacy value did not decrypt",
                        row["id"], field,
                    )
                    continue
                updates[field] = dojo_crypto_encrypt(decrypted)

            if updates:
                Tool_Configuration.objects.filter(id=row["id"]).update(**updates)
                upgraded += 1

    if upgraded:
        logger.info("Re-encrypted credentials for %d Tool_Configuration rows to AES-256-GCM", upgraded)


def noop_reverse(apps, schema_editor):
    # The "AES.2" values remain readable by prepare_for_view(); there is no need
    # (and no benefit) to downgrade them back to the legacy OFB scheme.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("dojo", "0269_normalize_blank_finding_components"),
    ]

    operations = [
        migrations.RunPython(reencrypt_tool_config_credentials, noop_reverse),
    ]
