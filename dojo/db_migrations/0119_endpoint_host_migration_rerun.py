# 2021-07-28 15:14
from django.db import migrations
from dojo.endpoint.utils import clean_hosts_run


def clean_hosts(apps, schema_editor):
    clean_hosts_run(apps=apps, change=True)


class Migration(migrations.Migration):
    dependencies = [
        ('dojo', '0118_remove_finding_images'),
    ]

    operations = [
        migrations.RunPython(clean_hosts)
    ]
