from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0272_reencrypt_tool_config_credentials_aes_gcm'),
    ]

    operations = [
        migrations.AddField(
            model_name='usercontactinfo',
            name='deduplication_execution_mode',
            field=models.CharField(blank=True, choices=[('async', 'Async (do not wait)'), ('async_wait', 'Async, wait for deduplication'), ('sync', 'Synchronous (block)')], help_text="Controls how import/reimport deduplication post-processing is executed. 'Async' dispatches it to the background and returns immediately (default). 'Async, wait for deduplication' dispatches to the background but waits for deduplication to finish before responding, so notifications and statistics reflect the deduplicated state. 'Synchronous' runs the import deduplication inline. Can be overridden per request. Independent of block_execution, which forces all async tasks (notifications, jira, ...) to the foreground.", max_length=20, null=True),
        ),
    ]
