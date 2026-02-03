# Generated manually for pghistory initial backfill

import logging

from django.conf import settings
from django.db import migrations

from dojo.auditlog import (
    get_tracked_models,
    process_model_backfill,
)

logger = logging.getLogger(__name__)


def backfill_pghistory_tables(apps, schema_editor):
    """
    Backfill pghistory tables with initial snapshots of existing records.

    This migration is fail-safe: if it fails for some reason, it will continue
    where it left off on the next run, as it only processes records that don't
    already have initial_backfill events.
    """
    # Skip if auditlog is not enabled
    if not settings.ENABLE_AUDITLOG:
        logger.info("pghistory is not enabled. Skipping backfill.")
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

    # Get all tracked models
    tracked_models = get_tracked_models()

    logger.info(f"Starting pghistory backfill for {len(tracked_models)} model(s)...")

    total_processed = 0
    for model_name in tracked_models:
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
            logger.error(f"Failed to backfill {model_name}: {e}", exc_info=True)
            # Continue with other models even if one fails
            continue

    logger.info(f"Pghistory backfill complete: Processed {total_processed:,} records")


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0249_findingreviewers_findingreviewersevent_and_more"),
    ]

    operations = [
        migrations.RunPython(
            backfill_pghistory_tables,
            reverse_code=migrations.RunPython.noop,
        ),
    ]

