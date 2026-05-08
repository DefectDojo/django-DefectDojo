"""Remove the Credential Manager feature.

Drops the `Cred_User`, `Cred_Mapping`, and `Cred_UserEvent` models, removes
the pghistory triggers that wrote into the latter, and removes the
`enable_credentials` switch from System_Settings. The Credential Manager
feature was deprecated in 2.57.0 and is end-of-life in 2.59.
"""

import pgtrigger.migrations
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0265_remove_stub_finding"),
    ]

    operations = [
        # Remove pghistory triggers that mirror Cred_User changes into
        # Cred_UserEvent. Triggers must be dropped before the source / event
        # tables can be removed.
        pgtrigger.migrations.RemoveTrigger(
            model_name="cred_user",
            name="insert_insert",
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name="cred_user",
            name="update_update",
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name="cred_user",
            name="delete_delete",
        ),
        # Drop the audit/event table (FKs from Cred_UserEvent → Cred_User get
        # cleaned up automatically as part of DeleteModel).
        migrations.DeleteModel(
            name="Cred_UserEvent",
        ),
        # Cred_Mapping holds an FK to Cred_User and must be dropped first.
        migrations.DeleteModel(
            name="Cred_Mapping",
        ),
        migrations.DeleteModel(
            name="Cred_User",
        ),
        # The UI toggle no longer has anything to gate.
        migrations.RemoveField(
            model_name="system_settings",
            name="enable_credentials",
        ),
    ]
