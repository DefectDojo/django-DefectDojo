import logging

from django.db import migrations
from django.db.models import Q
from django.db.models.functions import Trim

logger = logging.getLogger(__name__)

# Process blank components in bounded chunks so a single UPDATE never locks/writes
# "millions" of findings at once. Matches the page_size convention used by other
# Finding data migrations (e.g. 0201_populate_finding_sla_expiration_date).
BATCH_SIZE = 1000


def _normalize_field_to_null(Finding, field_name, batch_size=BATCH_SIZE):
    """
    Set blank (empty or whitespace-only) values of `field_name` to NULL, one
    seek-paged chunk at a time. Returns the number of rows updated.

    Pages over the blank queryset by `id__gt=last_id`: once a chunk is set to NULL it
    no longer matches the blank filter, so each iteration re-evaluates the filter and
    returns only not-yet-processed blank rows with a higher id. Rows at/below last_id
    were already updated in a prior page, so the loop touches only blank rows.
    """
    trimmed = f"{field_name}_trimmed"
    blank = (
        Finding.objects.annotate(**{trimmed: Trim(field_name)})
        .filter(Q(**{field_name: ""}) | Q(**{trimmed: ""}))
        .order_by("id")
    )

    total = 0
    last_id = 0
    while True:
        page_ids = list(blank.filter(id__gt=last_id).values_list("id", flat=True)[:batch_size])
        if not page_ids:
            break
        last_id = page_ids[-1]
        total += Finding.objects.filter(id__in=page_ids).update(**{field_name: None})
        logger.info("Normalized %d blank %s values so far...", total, field_name)

    return total


def normalize_blank_components(apps, schema_editor):
    """
    Convert blank (empty or whitespace-only) Finding component_name/component_version
    values to NULL so that findings without a component group together instead of
    appearing as a separate "None" component group (SC-13073).
    """
    Finding = apps.get_model("dojo", "Finding")

    name_updated = _normalize_field_to_null(Finding, "component_name")
    version_updated = _normalize_field_to_null(Finding, "component_version")

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
