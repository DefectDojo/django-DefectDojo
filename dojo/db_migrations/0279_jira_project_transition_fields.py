from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0278_global_search_fts_trigram_indexes'),
    ]

    operations = [
        migrations.AddField(
            model_name='jira_project',
            name='close_transition_fields',
            field=models.JSONField(blank=True, help_text='JIRA fields to send as part of the Close transition, e.g. {"resolution": {"name": "Won\'t Fix"}, "customfield_10200": "justification"}. Use this when the JIRA workflow requires fields on the close transition screen. Fields not on the transition screen are rejected by JIRA.', null=True, verbose_name='Close transition fields'),
        ),
        migrations.AddField(
            model_name='jira_project',
            name='reopen_transition_fields',
            field=models.JSONField(blank=True, help_text='JIRA fields to send as part of the Reopen transition, e.g. {"customfield_10201": "reopened by DefectDojo"}. Fields not on the transition screen are rejected by JIRA.', null=True, verbose_name='Reopen transition fields'),
        ),
    ]
