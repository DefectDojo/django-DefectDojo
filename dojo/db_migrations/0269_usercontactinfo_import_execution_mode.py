from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0268_release_authorization_to_pro'),
    ]

    operations = [
        migrations.AddField(
            model_name='usercontactinfo',
            name='import_execution_mode',
            field=models.CharField(blank=True, choices=[('async', 'Async (do not wait)'), ('async_wait', 'Async, wait for deduplication'), ('sync', 'Synchronous (block)')], help_text="Controls how import/reimport post-processing is executed. 'Async' returns immediately (default). 'Async, wait for deduplication' runs post-processing in the background but waits for deduplication to finish before responding, so notifications and statistics are accurate. 'Synchronous' runs everything inline (and blocks all async tasks in the foreground for this user, like the old 'block execution' flag). Can be overridden per request.", max_length=20, null=True),
        ),
    ]
