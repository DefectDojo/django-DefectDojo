from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0268_release_authorization_to_pro'),
    ]

    operations = [
        migrations.AddField(
            model_name='usercontactinfo',
            name='token_expiry',
            field=models.DateTimeField(blank=True, help_text="Optional expiry datetime for this user's API token. When set, requests using an expired token are rejected.", null=True),
        ),
    ]
