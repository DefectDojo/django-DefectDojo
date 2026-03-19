import logging

from django.db import migrations
from django.db.models import Count, Min

logger = logging.getLogger(__name__)


def deduplicate_language_types(apps, schema_editor):
    """
    Deduplicate Language_Type records by language name. For each set of
    duplicates, keep the lowest-ID record and reassign all Languages FK
    references to it, then delete the duplicates.
    """
    Language_Type = apps.get_model("dojo", "Language_Type")
    Languages = apps.get_model("dojo", "Languages")

    # Find language names that have duplicate Language_Type records
    dupes = (
        Language_Type.objects
        .values("language")
        .annotate(cnt=Count("id"), min_id=Min("id"))
        .filter(cnt__gt=1)
    )

    total_reassigned = 0
    total_deleted_types = 0
    total_deleted_languages = 0

    for dupe in dupes:
        canonical_id = dupe["min_id"]
        duplicate_ids = list(
            Language_Type.objects
            .filter(language=dupe["language"])
            .exclude(id=canonical_id)
            .values_list("id", flat=True)
        )

        # Reassign Languages FKs from duplicates to the canonical record
        reassigned = Languages.objects.filter(
            language_id__in=duplicate_ids,
        ).update(language_id=canonical_id)
        total_reassigned += reassigned

        # After reassignment, there may be duplicate (language, product) pairs.
        # Find and remove them, keeping the lowest-ID Languages record per pair.
        conflicting_pairs = (
            Languages.objects
            .filter(language_id=canonical_id)
            .values("language_id", "product_id")
            .annotate(cnt=Count("id"), min_id=Min("id"))
            .filter(cnt__gt=1)
        )
        for pair in conflicting_pairs:
            deleted_count, _ = (
                Languages.objects
                .filter(
                    language_id=pair["language_id"],
                    product_id=pair["product_id"],
                )
                .exclude(id=pair["min_id"])
                .delete()
            )
            total_deleted_languages += deleted_count

        # Delete the duplicate Language_Type records
        deleted_count, _ = Language_Type.objects.filter(id__in=duplicate_ids).delete()
        total_deleted_types += deleted_count

    if total_deleted_types:
        logger.info(
            "Deduplicated Language_Type: removed %d duplicate types, "
            "reassigned %d Languages FK references, "
            "removed %d duplicate Languages records",
            total_deleted_types,
            total_reassigned,
            total_deleted_languages,
        )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("dojo", "0261_remove_url_insert_insert_remove_url_update_update_and_more"),
    ]

    operations = [
        migrations.RunPython(deduplicate_language_types, noop_reverse),
    ]
