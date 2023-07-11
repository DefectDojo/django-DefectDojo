from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0125_sonarqube_clean"),
    ]

    operations = [
        migrations.AlterField(
            model_name="finding",
            name="publish_date",
            field=models.DateField(
                null=True,
                blank=True,
                verbose_name="Publish date",
                help_text="Date when this vulnerability was made publicly available.",
            ),
        )
    ]
