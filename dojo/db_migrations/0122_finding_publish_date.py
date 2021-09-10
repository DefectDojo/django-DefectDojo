from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0122_cobaltio_product"),
    ]

    operations = [
        migrations.AlterField(
            model_name="finding",
            name="publish_date",
            field=models.CharField(
                null=True,
                blank=True,
                verbose_name="Publish date",
                help_text="Date when this vulnerability was made publicly available.",
            ),
        )
    ]
