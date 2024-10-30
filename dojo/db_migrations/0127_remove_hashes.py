from auditlog.models import LogEntry
from django.db import migrations
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist
import json
import logging

logger = logging.getLogger(__name__)


def remove_hashes(apps, schema_editor):
    try:
        set_values(ContentType.objects.get(app_label='auth', model='user'))
    except ObjectDoesNotExist:
        logger.info('Content type for auth / user does not exist')
    try:
        set_values(ContentType.objects.get(app_label='dojo', model='cred_user'))
    except ObjectDoesNotExist:
        logger.info('Content type for dojo / cred_user does not exist')


def set_values(content_type):
    log_entries = LogEntry.objects.filter(content_type=content_type)
    for log_entry in log_entries:
        changes = json.loads(log_entry.changes)
        if 'password' in changes:
            attributes = changes['password']
            if len(attributes) == 2:
                attributes[0] = 'undisclosed'
                attributes[1] = 'undisclosed'
                changes['password'] = attributes
                log_entry.changes = json.dumps(changes)
                log_entry.save()


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0126_finding_publish_date'),
    ]

    operations = [
        migrations.RunPython(remove_hashes),
    ]
