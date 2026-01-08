"""
Audit logging configuration for DefectDojo.

This module handles registration of models with django-pghistory.
django-auditlog support has been removed.
"""
import logging
import os
import sys
import time

import pghistory
from dateutil.relativedelta import relativedelta
from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.db import connection, models
from django.utils import timezone

logger = logging.getLogger(__name__)

# FindingReviewers proxy model will be created lazily in register_django_pghistory_models()
# Cannot be defined at module level because Finding.reviewers.through requires
# Django's app registry to be ready (AppRegistryNotReady error)
# The function is called from DojoAppConfig.ready() which guarantees the registry is ready


def _flush_models_in_batches(models_to_flush, timestamp_field: str, retention_period: int, batch_size: int, max_batches: int, *, dry_run: bool = False) -> tuple[int, int, bool]:
    """
    Generic batched deletion by timestamp for a set of models.

    Returns (deleted_or_would_delete_total, batches_done_or_needed, reached_limit)
    """
    # Use a timestamp and not a date. this allows for efficient databse index use.
    cutoff_dt = timezone.now() - relativedelta(months=retention_period)
    logger.info("Audit flush cutoff datetime: %s (retention_period=%s months)", cutoff_dt, retention_period)

    total_deleted = 0
    total_batches = 0
    reached_any_limit = False

    for Model in models_to_flush:
        deleted_total = 0
        batches_done = 0
        filter_kwargs = {f"{timestamp_field}__lt": cutoff_dt}
        last_pk = None
        verb = "Would delete" if dry_run else "Deleted"

        while batches_done < max_batches:
            batch_qs = Model.objects.filter(**filter_kwargs)
            if last_pk is not None:
                batch_qs = batch_qs.filter(pk__gt=last_pk)
            batch_qs = batch_qs.order_by("pk")

            pks = list(batch_qs.values_list("pk", flat=True)[:batch_size])
            if not pks:
                if batches_done == 0:
                    logger.info("No outdated %s entries found", Model._meta.object_name)
                break

            if dry_run:
                deleted_count = len(pks)
            else:
                qs = Model.objects.filter(pk__in=pks)
                deleted_count = int(qs._raw_delete(qs.db))

            deleted_total += deleted_count
            batches_done += 1
            last_pk = pks[-1]

            logger.info(
                "%s %s batch %s (size ~%s), total %s: %s",
                verb,
                Model._meta.object_name,
                batches_done,
                batch_size,
                verb.lower(),
                deleted_total,
            )

        total_deleted += deleted_total
        total_batches += batches_done
        if batches_done >= max_batches:
            reached_any_limit = True

    return total_deleted, total_batches, reached_any_limit


def _iter_pghistory_event_models():
    """Yield pghistory Event models registered under the dojo app."""
    for model in apps.get_app_config("dojo").get_models():
        if model._meta.object_name.endswith("Event"):
            # Ensure the model has pgh_created_at field
            if any(f.name == "pgh_created_at" for f in model._meta.fields):
                yield model


def _flush_pghistory_events(retention_period: int, batch_size: int, max_batches: int, *, dry_run: bool = False) -> tuple[int, int, bool]:
    models_to_flush = list(_iter_pghistory_event_models())
    return _flush_models_in_batches(models_to_flush, "pgh_created_at", retention_period, batch_size, max_batches, dry_run=dry_run)


def run_flush_auditlog(retention_period: int | None = None,
                       batch_size: int | None = None,
                       max_batches: int | None = None,
                       *,
                       dry_run: bool = False) -> tuple[int, int, bool]:
    """
    Deletes audit entries older than the configured retention from django-pghistory log entries.

    Returns a tuple of (deleted_total, batches_done, reached_limit).
    """
    retention_period = retention_period if retention_period is not None else getattr(settings, "AUDITLOG_FLUSH_RETENTION_PERIOD", -1)
    if retention_period < 0:
        logger.info("Flushing audit logs is disabled")
        return 0, 0, False

    batch_size = batch_size if batch_size is not None else getattr(settings, "AUDITLOG_FLUSH_BATCH_SIZE", 1000)
    max_batches = max_batches if max_batches is not None else getattr(settings, "AUDITLOG_FLUSH_MAX_BATCHES", 100)

    phase = "DRY RUN" if dry_run else "Cleanup"
    logger.info("Running %s for django-pghistory entries with %d Months retention across all backends", phase, retention_period)
    p_deleted, p_batches, p_limit = _flush_pghistory_events(retention_period, batch_size, max_batches, dry_run=dry_run)

    verb = "would delete" if dry_run else "deleted"
    logger.info("Audit flush summary: pghistory %s=%s batches=%s", verb, p_deleted, p_batches)

    return p_deleted, p_batches, bool(p_limit)


def register_django_pghistory_models():
    """
    Register models with django-pghistory (always called to avoid migrations).

    Note: This function is always called regardless of audit logging settings because:
    1. Django migrations are generated based on model registration at import time
    2. If pghistory models are not registered, Django will try to create migrations
       to remove the pghistory tables when the models are not found
    3. This would cause migration conflicts and database inconsistencies
    4. By always registering the models, we ensure the database schema remains
       stable while controlling audit behavior through trigger enable/disable
    So we always register the models and make migrations for them.
    Then we control the enabling/disabling by enabling/disabling the underlying database
    triggers.
    """
    # Import models inside function to avoid AppRegistryNotReady errors
    from dojo.models import (  # noqa: PLC0415
        Cred_User,
        Dojo_User,
        Endpoint,
        Engagement,
        Finding,
        Finding_Group,
        Finding_Template,
        Notification_Webhooks,
        Product,
        Product_Type,
        Risk_Acceptance,
        Test,
    )

    # Only log during actual application startup, not during shell commands
    if "shell" not in sys.argv:
        logger.info("Registering models with django-pghistory")

    # Register models with pghistory for tracking changes
    # Using pghistory.track() as a decorator function (correct syntax)
    # The function returns a decorator that should be applied to the model class

    # Track Dojo_User with excluded fields
    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        exclude=["password"],
        # add some indexes manually so we don't have to define a customer phistory Event model with overridden fields.
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Dojo_User)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Endpoint)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Engagement)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Finding)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Finding_Group)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Product_Type)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Product)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Test)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Risk_Acceptance)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Finding_Template)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        exclude=["password"],
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Cred_User)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        exclude=["header_name", "header_value"],
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Notification_Webhooks)

    # Track Finding.reviewers ManyToMany relationship
    # Create a proxy model for the through table as per pghistory docs:
    # https://django-pghistory.readthedocs.io/en/2.4.2/tutorial.html#tracking-many-to-many-events
    # Note: For auto-generated through models, we don't specify obj_fk/obj_field
    # as Django doesn't allow foreign keys to auto-generated through models
    #
    # We must create the proxy model here (not at module level) because:
    # 1. Finding.reviewers.through requires Django's app registry to be ready
    # 2. This function is called from DojoAppConfig.ready() which guarantees registry is ready
    # 3. We check if it already exists to avoid re-registration warnings
    #
    # Note: This pattern is not explicitly documented in Django's official documentation.
    # Django docs mention AppRegistryNotReady and AppConfig.ready() in general terms, but
    # don't specifically cover proxy models for auto-generated ManyToMany through tables.
    # This is a common pattern used by libraries like django-pghistory and is necessary
    # because accessing Model.field.through at module import time triggers AppRegistryNotReady.
    reviewers_through = Finding._meta.get_field("reviewers").remote_field.through

    class FindingReviewers(reviewers_through):
        class Meta:
            proxy = True

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "db_table": "dojo_finding_reviewersevent",
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(FindingReviewers)

    # Only log during actual application startup, not during shell commands
    if "shell" not in sys.argv:
        logger.info("Successfully registered models with django-pghistory")


def configure_pghistory_triggers():
    """
    Configure pghistory triggers based on audit settings.

    This function should be called after Django startup and migrations to properly
    enable/disable pghistory triggers without database access warnings.
    """
    if not settings.ENABLE_AUDITLOG:
        logger.info("Audit logging disabled - disabling pghistory triggers")
        try:
            call_command("pgtrigger", "disable")
            logger.info("Successfully disabled pghistory triggers")
        except Exception as e:
            logger.error(f"Failed to disable pghistory triggers: {e}")
            raise
    else:
        # Only pghistory is supported now
        try:
            call_command("pgtrigger", "enable")
            logger.info("Successfully enabled pghistory triggers")
        except Exception as e:
            logger.error(f"Failed to enable pghistory triggers: {e}")
            raise


def configure_audit_system():
    """
    Configure the audit system based on settings.

    django-auditlog is no longer supported. Only django-pghistory is allowed.
    """
    # Only log during actual application startup, not during shell commands
    log_enabled = "shell" not in sys.argv

    # Fail if DD_AUDITLOG_TYPE is still configured (removed setting)
    auditlog_type_env = os.environ.get("DD_AUDITLOG_TYPE")
    if auditlog_type_env:
        error_msg = (
            "DD_AUDITLOG_TYPE environment variable is no longer supported. "
            "DefectDojo now exclusively uses django-pghistory for audit logging. "
            "Please remove DD_AUDITLOG_TYPE from your environment configuration. "
            "All new audit entries will be created using django-pghistory automatically."
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    # Fail if AUDITLOG_TYPE is manually set in settings files (removed setting)
    if hasattr(settings, "AUDITLOG_TYPE"):
        error_msg = (
            "AUDITLOG_TYPE setting is no longer supported. "
            "DefectDojo now exclusively uses django-pghistory for audit logging. "
            "Please remove AUDITLOG_TYPE from your settings file (settings.dist.py or local_settings.py). "
            "All new audit entries will be created using django-pghistory automatically."
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    if not settings.ENABLE_AUDITLOG:
        if log_enabled:
            logger.info("Audit logging disabled")
        return

    if log_enabled:
        logger.info("Audit logging configured: django-pghistory")


# Backfill functions for pghistory tables
def get_excluded_fields(model_name):
    """Get the list of excluded fields for a specific model from pghistory configuration."""
    # Define excluded fields for each model (matching auditlog.py)
    excluded_fields_map = {
        "Dojo_User": ["password"],
        "Product": ["updated"],  # This is the key change
        "Cred_User": ["password"],
        "Notification_Webhooks": ["header_name", "header_value"],
    }
    return excluded_fields_map.get(model_name, [])


def get_table_names(model_name):
    """Get the source table name and event table name for a model."""
    # Handle special cases for table naming
    if model_name == "Dojo_User":
        table_name = "dojo_dojo_user"
        event_table_name = "dojo_dojo_userevent"
    elif model_name == "Product_Type":
        table_name = "dojo_product_type"
        event_table_name = "dojo_product_typeevent"
    elif model_name == "Finding_Group":
        table_name = "dojo_finding_group"
        event_table_name = "dojo_finding_groupevent"
    elif model_name == "Risk_Acceptance":
        table_name = "dojo_risk_acceptance"
        event_table_name = "dojo_risk_acceptanceevent"
    elif model_name == "Finding_Template":
        table_name = "dojo_finding_template"
        event_table_name = "dojo_finding_templateevent"
    elif model_name == "Cred_User":
        table_name = "dojo_cred_user"
        event_table_name = "dojo_cred_userevent"
    elif model_name == "Notification_Webhooks":
        table_name = "dojo_notification_webhooks"
        event_table_name = "dojo_notification_webhooksevent"
    elif model_name == "FindingReviewers":
        # M2M through table: Django creates dojo_finding_reviewers for Finding.reviewers
        table_name = "dojo_finding_reviewers"
        event_table_name = "dojo_finding_reviewersevent"
    else:
        table_name = f"dojo_{model_name.lower()}"
        event_table_name = f"dojo_{model_name.lower()}event"
    return table_name, event_table_name


def check_tables_exist(table_name, event_table_name):
    """Check if both source and event tables exist."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = %s
            )
        """, [table_name])
        table_exists = cursor.fetchone()[0]

        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = %s
            )
        """, [event_table_name])
        event_table_exists = cursor.fetchone()[0]

    return table_exists, event_table_exists


def process_model_backfill(
    model_name,
    batch_size=10000,
    *,
    dry_run=False,
    progress_callback=None,
):
    """
    Process a single model's backfill using PostgreSQL COPY.

    Args:
        model_name: Name of the model to backfill
        batch_size: Number of records to process in each batch
        dry_run: If True, only show what would be done without creating events
        progress_callback: Optional callable that receives (message, style) tuples
                          for progress updates. If None, uses logger.info

    Returns:
        tuple: (processed_count, records_per_second)

    """
    if progress_callback is None:
        def progress_callback(msg, style=None):
            logger.info(msg)

    try:
        table_name, event_table_name = get_table_names(model_name)

        # Check if tables exist
        table_exists, event_table_exists = check_tables_exist(table_name, event_table_name)

        if not table_exists:
            progress_callback(f"  Table {table_name} not found")
            return 0, 0.0

        if not event_table_exists:
            progress_callback(
                f"  Event table {event_table_name} not found. "
                f"Is {model_name} tracked by pghistory?",
                "ERROR",
            )
            return 0, 0.0

        # Get total count using raw SQL
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            total_count = cursor.fetchone()[0]

        if total_count == 0:
            progress_callback(f"  No records found for {model_name}")
            return 0, 0.0

        progress_callback(f"  Found {total_count:,} records")

        # Get excluded fields
        excluded_fields = get_excluded_fields(model_name)

        # Check if records already have initial_backfill events using raw SQL
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {event_table_name} WHERE pgh_label = 'initial_backfill'")
            existing_count = cursor.fetchone()[0]

        # Get records that need backfill using raw SQL
        with connection.cursor() as cursor:
            cursor.execute(f"""
                SELECT COUNT(*) FROM {table_name} t
                WHERE NOT EXISTS (
                    SELECT 1 FROM {event_table_name} e
                    WHERE e.pgh_obj_id = t.id AND e.pgh_label = 'initial_backfill'
                )
            """)
            backfill_count = cursor.fetchone()[0]

        # Log the breakdown
        progress_callback(f"  Records with initial_backfill events: {existing_count:,}")
        progress_callback(f"  Records needing initial_backfill events: {backfill_count:,}")

        if backfill_count == 0:
            progress_callback(f"  ✓ All {total_count:,} records already have initial_backfill events", "SUCCESS")
            return total_count, 0.0

        if dry_run:
            progress_callback(f"  Would process {backfill_count:,} records using COPY...")
            return backfill_count, 0.0

        # Get event table columns using raw SQL (excluding auto-generated pgh_id)
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = %s AND column_name != 'pgh_id'
                ORDER BY ordinal_position
            """, [event_table_name])
            event_columns = [row[0] for row in cursor.fetchall()]

        # Get all IDs that need backfill first
        with connection.cursor() as cursor:
            cursor.execute(f"""
                SELECT t.id FROM {table_name} t
                WHERE NOT EXISTS (
                    SELECT 1 FROM {event_table_name} e
                    WHERE e.pgh_obj_id = t.id AND e.pgh_label = 'initial_backfill'
                )
                ORDER BY t.id
            """)
            ids_to_process = [row[0] for row in cursor.fetchall()]

        if not ids_to_process:
            progress_callback("  No records need backfill")
            return 0, 0.0

        # Process records in batches using raw SQL
        processed = 0
        batch_start_time = time.time()
        model_start_time = time.time()  # Track model start time

        # Get column names for the source table
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = %s
                ORDER BY ordinal_position
            """, [table_name])
            source_columns = [row[0] for row in cursor.fetchall()]

        # Filter out excluded fields from source columns
        source_columns = [col for col in source_columns if col not in excluded_fields]

        # Find the index of the 'id' column for pgh_obj_id mapping
        try:
            id_column_index = source_columns.index("id")
        except ValueError:
            # If id is excluded (shouldn't happen), fall back to first column
            id_column_index = 0
            progress_callback("  Warning: 'id' column not found in source columns, using first column", "WARNING")

        # Process in batches
        consecutive_failures = 0
        max_failures = 3

        for i in range(0, len(ids_to_process), batch_size):
            batch_ids = ids_to_process[i:i + batch_size]

            # Log progress every 10 batches
            if i > 0 and i % (batch_size * 10) == 0:
                progress_callback(f"  Processing batch starting at index {i:,}...")

            # Get batch of records using raw SQL with specific IDs
            columns_str = ", ".join(source_columns)
            placeholders = ", ".join(["%s"] * len(batch_ids))
            query = f"""
                SELECT {columns_str} FROM {table_name} t
                WHERE t.id IN ({placeholders})
                ORDER BY t.id
            """

            with connection.cursor() as cursor:
                cursor.execute(query, batch_ids)
                batch_rows = cursor.fetchall()

            if not batch_rows:
                progress_callback(f"  No records found for batch at index {i}")
                continue

            # Use PostgreSQL COPY
            try:
                # Use PostgreSQL COPY with psycopg3 syntax
                with connection.cursor() as cursor:
                    # Get the underlying raw cursor to bypass Django's wrapper
                    raw_cursor = cursor.cursor
                    # Use the copy method (psycopg3 syntax)
                    copy_sql = f"COPY {event_table_name} ({', '.join(event_columns)}) FROM STDIN WITH (FORMAT text, DELIMITER E'\\t')"

                    # Use psycopg3 copy syntax as per documentation
                    # Prepare data as list of tuples for write_row()
                    records = []
                    for row in batch_rows:
                        row_data = []

                        # Create a mapping of source columns to values
                        source_values = {}
                        for idx, value in enumerate(row):
                            field_name = source_columns[idx]
                            source_values[field_name] = value

                        # Build row data in the order of event_columns
                        for col in event_columns:
                            if col == "pgh_created_at":
                                row_data.append(timezone.now())
                            elif col == "pgh_label":
                                row_data.append("initial_backfill")
                            elif col == "pgh_obj_id":
                                # Use the id column index instead of assuming position
                                row_data.append(row[id_column_index] if row[id_column_index] is not None else None)
                            elif col == "pgh_context_id":
                                row_data.append(None)  # Empty for backfilled events
                            elif col in source_values:
                                row_data.append(source_values[col])
                            else:
                                row_data.append(None)  # Default NULL value

                        records.append(tuple(row_data))

                    # Use COPY with write_row() as per psycopg3 docs
                    with raw_cursor.copy(copy_sql) as copy:
                        for record in records:
                            copy.write_row(record)
                    progress_callback("  COPY operation completed using write_row")

                    # Commit the transaction to persist the data
                    raw_cursor.connection.commit()

                    # Debug: Check if data was inserted
                    raw_cursor.execute(f"SELECT COUNT(*) FROM {event_table_name} WHERE pgh_label = 'initial_backfill'")
                    count = raw_cursor.fetchone()[0]
                    progress_callback(f"  Records in event table after batch: {count}")

                batch_processed = len(batch_rows)
                processed += batch_processed
                consecutive_failures = 0  # Reset failure counter on success

                # Calculate timing
                batch_end_time = time.time()
                batch_duration = batch_end_time - batch_start_time
                batch_records_per_second = batch_processed / batch_duration if batch_duration > 0 else 0

                # Log progress
                progress = (processed / backfill_count) * 100
                progress_callback(
                    f"  Processed {processed:,}/{backfill_count:,} records ({progress:.1f}%) - "
                    f"Last batch: {batch_duration:.2f}s ({batch_records_per_second:.1f} records/sec)",
                )

                batch_start_time = time.time()  # Reset for next batch

            except Exception as e:
                consecutive_failures += 1
                logger.error(f"Bulk insert failed for {model_name} batch: {e}")
                progress_callback(f"  Bulk insert failed: {e}", "ERROR")
                # Log more details about the error
                progress_callback(f"  Processed {processed:,} records before failure")

                if consecutive_failures >= max_failures:
                    progress_callback(f"  Too many consecutive failures ({consecutive_failures}), stopping processing", "ERROR")
                    break

                # Continue with next batch instead of breaking
                continue

        # Calculate total timing
        model_end_time = time.time()
        total_duration = model_end_time - model_start_time
        records_per_second = processed / total_duration if total_duration > 0 else 0

        progress_callback(
            f"  ✓ Completed {model_name}: {processed:,} records in {total_duration:.2f}s "
            f"({records_per_second:.1f} records/sec)",
            "SUCCESS",
        )
    except Exception as e:
        progress_callback(f"  ✗ Failed to process {model_name}: {e}", "ERROR")
        logger.exception(f"Error processing {model_name}")
        return 0, 0.0
    else:
        return processed, records_per_second


def get_tracked_models():
    """Get the list of models tracked by pghistory."""
    return [
        "Dojo_User", "Endpoint", "Engagement", "Finding", "Finding_Group",
        "Product_Type", "Product", "Test", "Risk_Acceptance",
        "Finding_Template", "Cred_User", "Notification_Webhooks",
        "FindingReviewers",  # M2M through table for Finding.reviewers
    ]
