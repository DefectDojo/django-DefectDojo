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
        # State only: forget the models and their triggers so they no longer
        # have to be defined in dojo/models.py. There are no database_operations
        # so the dojo_cred_user, dojo_cred_mapping, and dojo_cred_userevent
        # tables and the cred_user pghistory triggers are preserved for
        # downgrades.
        migrations.SeparateDatabaseAndState(
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
            ],
        ),
        # Drop the enable_credentials field from state but keep the column for
        # downgrades. The model no longer supplies a value on INSERT, so give
        # the column a server-side default (the field defaulted to True) to
        # keep new System_Settings rows satisfying its NOT NULL constraint.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveField(
                    model_name="system_settings",
                    name="enable_credentials",
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    sql="ALTER TABLE dojo_system_settings ALTER COLUMN enable_credentials SET DEFAULT true;",
                    reverse_sql="ALTER TABLE dojo_system_settings ALTER COLUMN enable_credentials DROP DEFAULT;",
                ),
            ],
        ),
    ]
