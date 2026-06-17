import logging

from django.db import migrations
from django.db.models import Q
from django.db.models.functions import Trim

logger = logging.getLogger(__name__)


def normalize_blank_components(apps, schema_editor):
    """
    Convert blank (empty or whitespace-only) Finding component_name/component_version
    values to NULL so that findings without a component group together instead of
    appearing as a separate "None" component group (SC-13073).
    """
    Finding = apps.get_model("dojo", "Finding")

    blank_name = Finding.objects.annotate(
        component_name_trimmed=Trim("component_name"),
    ).filter(Q(component_name="") | Q(component_name_trimmed=""))
    name_updated = blank_name.update(component_name=None)

    blank_version = Finding.objects.annotate(
        component_version_trimmed=Trim("component_version"),
    ).filter(Q(component_version="") | Q(component_version_trimmed=""))
    version_updated = blank_version.update(component_version=None)

    if name_updated or version_updated:
        logger.info(
            "Normalized blank Finding components to NULL: %d component_name, %d component_version",
            name_updated,
            version_updated,
        )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("dojo", "0268_release_authorization_to_pro"),
    ]

    operations = [
        migrations.RunPython(normalize_blank_components, noop_reverse),
    ]
