"""Remove the Stub Findings feature (state only).

Drops the ``Stub_Finding`` model from Django's state but leaves the
``dojo_stub_finding`` table in place so a downgrade to a release that still
defines the model keeps its data. Stub Findings was deprecated in 2.57.0 and
is end-of-life in 2.59. The model has no inbound foreign keys, so the removal
is self-contained.

Note: rebase the filename and the ``dependencies`` tuple to point at
whatever the latest migration is at merge time if another migration has
landed first.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0264_alter_url_identity_hash_alter_urlevent_identity_hash"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # State only: forget the model so it no longer has to be defined
            # in dojo/models.py. database_operations is intentionally empty so
            # the dojo_stub_finding table is preserved for downgrades.
            state_operations=[
                migrations.DeleteModel(
                    name="Stub_Finding",
                ),
            ],
        ),
    ]
