"""Remove the Credential Manager feature (state only).

Removes the `Cred_User`, `Cred_Mapping`, and `Cred_UserEvent` models, their
pghistory triggers, and the `enable_credentials` switch from System_Settings
from Django's state, but leaves the underlying tables, columns, and triggers
in the database so a downgrade to a release that still defines them keeps its
data. The Credential Manager feature was deprecated in 2.57.0 and is
end-of-life in 2.59.
"""

import pgtrigger.migrations
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0265_remove_stub_finding"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # State only: forget the models, triggers, and field so they no
            # longer have to be defined in dojo/models.py. database_operations
            # is intentionally empty so the dojo_cred_user, dojo_cred_mapping,
            # and dojo_cred_userevent tables, the cred_user pghistory triggers,
            # and the system_settings.enable_credentials column are all
            # preserved for downgrades.
            state_operations=[
                # Drop the pghistory triggers from state before the model they
                # hang off of is removed.
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
                # Cred_UserEvent FKs Cred_User; Cred_Mapping FKs Cred_User too,
                # so both come out of state before Cred_User itself.
                migrations.DeleteModel(
                    name="Cred_UserEvent",
                ),
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
            ],
        ),
    ]
