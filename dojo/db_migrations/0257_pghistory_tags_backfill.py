# Generated manually for pghistory tag models initial backfill

import logging

from django.conf import settings
from django.db import migrations

from dojo.auditlog import process_model_backfill

logger = logging.getLogger(__name__)

# Tag through models to backfill
TAG_MODELS = [
    "FindingTags",
    "FindingInheritedTags",
    "ProductTags",
    "EngagementTags",
    "EngagementInheritedTags",
    "TestTags",
    "TestInheritedTags",
    "EndpointTags",
    "EndpointInheritedTags",
    "FindingTemplateTags",
    "AppAnalysisTags",
    "ObjectsProductTags",
]


def backfill_pghistory_tag_tables(apps, schema_editor):
    """
    Backfill pghistory tag tables with initial snapshots of existing records.

    This migration is fail-safe: if it fails for some reason, it will continue
    where it left off on the next run, as it only processes records that don't
    already have initial_backfill events.
    """
    # Skip if auditlog is not enabled
    if not settings.ENABLE_AUDITLOG:
        logger.info("pghistory is not enabled. Skipping tag backfill.")
        return

    # Check if we can use COPY (PostgreSQL only)
    if settings.DATABASES["default"]["ENGINE"] != "django.db.backends.postgresql":
        logger.warning(
            "COPY operations only available with PostgreSQL. "
            "Skipping backfill. Use the pghistory_backfill command instead.",
        )
        return

    # Progress callback for migration logging
    def progress_callback(msg, style=None):
        """Progress callback that logs to Django's logger."""
        if style == "ERROR":
            logger.error(msg)
        elif style == "WARNING":
            logger.warning(msg)
        elif style == "SUCCESS":
            logger.info(msg)
        elif style == "DEBUG":
            logger.debug(msg)
        else:
            logger.info(msg)

    logger.info(f"Starting pghistory backfill for {len(TAG_MODELS)} tag model(s)...")

    total_processed = 0
    for model_name in TAG_MODELS:
        logger.info(f"Processing {model_name}...")
        try:
            processed, _ = process_model_backfill(
                model_name=model_name,
                batch_size=10000,
                dry_run=False,
                progress_callback=progress_callback,
            )
            total_processed += processed
        except Exception as e:
            logger.exception(f"Failed to backfill {model_name}: {e}")
            # Continue with other models even if one fails
            continue

    logger.info(f"Pghistory tag backfill complete: Processed {total_processed:,} records")


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0256_pghistory_for_tags_models"),
    ]

    operations = [
        migrations.RunPython(
            backfill_pghistory_tag_tables,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
