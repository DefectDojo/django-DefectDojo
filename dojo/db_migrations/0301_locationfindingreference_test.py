import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    """
    Attribute each location reference to the test that reported it (first half).

    Adds a nullable ``test`` column and fills it from the finding's own test, which is the only
    test any existing row could have come from. 0302 then makes the column required and moves
    the uniqueness onto (location, finding, test). The two halves are separate migrations so the
    backfill's row writes and the later ALTER TABLE never share a transaction.
    """

    dependencies = [
        ("dojo", "0300_finding_upper_title_index"),
    ]

    operations = [
        migrations.AddField(
            model_name="locationfindingreference",
            name="test",
            field=models.ForeignKey(
                help_text="The test that reported this location for the finding",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="location_finding_references",
                to="dojo.test",
            ),
        ),
        migrations.RunSQL(
            sql="""
                UPDATE dojo_locationfindingreference AS ref
                SET test_id = finding.test_id
                FROM dojo_finding AS finding
                WHERE finding.id = ref.finding_id AND ref.test_id IS NULL
            """,
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
