"""
Remove the ``ui_use_tailwind`` UI opt-in from UserContactInfo.

Drops the classic-vs-Tailwind opt-in added in 0267. The database drop is made
idempotent (``DROP COLUMN IF EXISTS``): an instance can reach this migration
without the column physically present — the OSS->Pro upgrade fixtures, and any
database whose recorded migration history skews from its physical schema, hit
exactly that — and a plain ``RemoveField`` emits an unconditional
``ALTER TABLE ... DROP COLUMN`` that then fails with
``column "ui_use_tailwind" ... does not exist``. Splitting the state removal
from an ``IF EXISTS`` database drop keeps Django's model state correct while
tolerating the absent column. UserContactInfo is not pghistory-tracked, so no
event table carries the column and a raw ``ALTER TABLE`` is sufficient.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0292_review_request_notes_public"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveField(
                    model_name="usercontactinfo",
                    name="ui_use_tailwind",
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    sql="ALTER TABLE dojo_usercontactinfo DROP COLUMN IF EXISTS ui_use_tailwind;",
                    # Reverse re-adds the column with its original definition (0267:
                    # BooleanField(default=False)) so a downgrade restores a working schema.
                    reverse_sql=(
                        "ALTER TABLE dojo_usercontactinfo "
                        "ADD COLUMN IF NOT EXISTS ui_use_tailwind boolean NOT NULL DEFAULT false;"
                    ),
                ),
            ],
        ),
    ]
