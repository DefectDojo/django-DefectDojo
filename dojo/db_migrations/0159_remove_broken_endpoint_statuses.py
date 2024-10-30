from django.db import migrations
from dojo.endpoint.utils import remove_broken_endpoint_statuses


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0158_vulnerability_id'),
    ]

    def remove_broken_endpoint_statuses_local(apps, schema_editor):
        remove_broken_endpoint_statuses(apps=apps)

    operations = [
        migrations.RunPython(remove_broken_endpoint_statuses_local)
    ]
