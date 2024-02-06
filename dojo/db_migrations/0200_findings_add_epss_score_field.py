
from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0199_whitesource_to_mend'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='epss_score',
            field=models.FloatField(blank=True, default=None, help_text='EPSS score for the CVE. Describes how likely it is the vulnerability will be exploited in the next 30 days.', max_length=6),
        ),
        migrations.AddField(
            model_name='finding',
            name='epss_percentile',
            field=models.FloatField(blank=True, default=None, help_text='EPSS percentile for the CVE. Describes how many CVEs are scored at or below this one.', max_length=6),
        ),
        migrations.AddField(
            model_name='finding_template',
            name='epss_score',
            field=models.FloatField(blank=True, default=None, help_text='EPSS score for the CVE. Describes how likely it is the vulnerability will be exploited in the next 30 days.', max_length=6),
        ),
         migrations.AddField(
            model_name='finding_template',
            name='epss_percentile',
            field=models.FloatField(blank=True, default=None, help_text='EPSS percentile for the CVE. Describes how many CVEs are scored at or below this one.', max_length=6),
        ),
    ]
