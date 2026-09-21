from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0293_remove_usercontactinfo_ui_use_tailwind"),
    ]

    operations = [
        migrations.AddField(
            model_name="usercontactinfo",
            name="token_expiry",
            field=models.DateTimeField(blank=True, help_text="Explicit expiry for this user's API token. Overrides the instance-wide default from DD_API_TOKEN_DEFAULT_EXPIRY_DAYS. Leave empty to use that default. Once the effective expiry has passed the token is rejected at authentication.", null=True),
        ),
    ]
