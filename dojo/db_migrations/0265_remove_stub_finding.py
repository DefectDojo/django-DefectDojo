"""Remove the Stub Findings feature.

Drops the ``Stub_Finding`` model. Stub Findings was deprecated in 2.57.0 and
is end-of-life in 2.59. The model has no inbound foreign keys, so the
deletion is self-contained.

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
        migrations.DeleteModel(
            name="Stub_Finding",
        ),
    ]
