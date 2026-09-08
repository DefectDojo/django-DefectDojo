from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0294_usercontactinfo_token_expiry"),
    ]

    operations = [
        migrations.AddField(
            model_name="usercontactinfo",
            name="language",
            field=models.CharField(blank=True, default="", help_text="Preferred language for the DefectDojo UI. Leave blank to use the instance default.", max_length=12, verbose_name="Language"),
        ),
    ]
