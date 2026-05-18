from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0264_alter_url_identity_hash_alter_urlevent_identity_hash"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="component_purl",
            field=models.CharField(
                blank=True,
                help_text="Package URL (PURL) of the affected component (e.g. pkg:pypi/requests@2.25.1).",
                max_length=500,
                null=True,
                verbose_name="Component PURL",
            ),
        ),
    ]
