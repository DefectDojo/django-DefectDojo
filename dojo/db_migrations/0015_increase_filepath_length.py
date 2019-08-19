from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0014_jira_conf_resolution_mappings'),
    ]

    operations = [
        migrations.AlterField(
            model_name='finding',
            name='file_path',
            field=models.CharField(blank=True, max_length=4000, null=True),
        ),
    ]
