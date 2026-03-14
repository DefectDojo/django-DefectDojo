from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0261_remove_url_insert_insert_remove_url_update_update_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="system_settings",
            name="max_import_history",
            field=models.IntegerField(
                blank=True,
                null=True,
                default=None,
                verbose_name="Max Import History",
                help_text="When set, the oldest import history records will be deleted when a test exceeds this number of imports. Leave empty to keep all history.",
            ),
        ),
    ]
