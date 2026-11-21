import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    """Make the reference's test required and unique per (location, finding, test) (second half of 0301)."""

    dependencies = [
        ("dojo", "0301_locationfindingreference_test"),
    ]

    operations = [
        migrations.AlterField(
            model_name="locationfindingreference",
            name="test",
            field=models.ForeignKey(
                help_text="The test that reported this location for the finding",
                on_delete=django.db.models.deletion.CASCADE,
                related_name="location_finding_references",
                to="dojo.test",
            ),
        ),
        migrations.RemoveConstraint(
            model_name="locationfindingreference",
            name="unique_location_and_finding",
        ),
        # Nothing forward. Backward, the old (location, finding) constraint cannot be restored
        # while a location has a row from more than one test, so each pair keeps one row: the
        # finding's own test's if it has one, else the oldest.
        migrations.RunSQL(
            sql=migrations.RunSQL.noop,
            reverse_sql="""
                DELETE FROM dojo_locationfindingreference AS ref
                USING (
                    SELECT ref.id,
                           ROW_NUMBER() OVER (
                               PARTITION BY ref.location_id, ref.finding_id
                               ORDER BY (ref.test_id = finding.test_id) DESC, ref.id
                           ) AS rank
                    FROM dojo_locationfindingreference AS ref
                    JOIN dojo_finding AS finding ON finding.id = ref.finding_id
                ) AS ranked
                WHERE ranked.id = ref.id AND ranked.rank > 1
            """,
        ),
        migrations.AddConstraint(
            model_name="locationfindingreference",
            constraint=models.UniqueConstraint(
                fields=("location", "finding", "test"),
                name="unique_location_finding_and_test",
            ),
        ),
    ]
