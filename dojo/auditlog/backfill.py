"""
Backfill operations for pghistory event tables.

Used by management commands and one-shot data migrations. Per-batch failures
are logged and skipped (up to 3 consecutive failures before giving up on the
model); a model-level failure logs the traceback and returns ``(0, 0.0)`` so
batch callers can continue with the next model.
"""
import logging
import time

from django.db import connection
from django.utils import timezone

logger = logging.getLogger(__name__)


def get_excluded_fields(model_name):
    """Get the list of excluded fields for a specific model from pghistory configuration."""
    excluded_fields_map = {
        "Dojo_User": ["password"],
        "Product": ["updated"],
        "Cred_User": ["password"],
        "Notification_Webhooks": ["header_name", "header_value"],
    }
    return excluded_fields_map.get(model_name, [])


def get_table_names(model_name):
    """Get the source table name and event table name for a model."""
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
    # Tag through tables (tagulous auto-generated)
    elif model_name == "FindingTags":
        table_name = "dojo_finding_tags"
        event_table_name = "dojo_finding_tagsevent"
    elif model_name == "ProductTags":
        table_name = "dojo_product_tags"
        event_table_name = "dojo_product_tagsevent"
    elif model_name == "EngagementTags":
        table_name = "dojo_engagement_tags"
        event_table_name = "dojo_engagement_tagsevent"
    elif model_name == "TestTags":
        table_name = "dojo_test_tags"
        event_table_name = "dojo_test_tagsevent"
    elif model_name == "EndpointTags":
        table_name = "dojo_endpoint_tags"
        event_table_name = "dojo_endpoint_tagsevent"
    elif model_name == "FindingTemplateTags":
        table_name = "dojo_finding_template_tags"
        event_table_name = "dojo_finding_template_tagsevent"
    elif model_name == "AppAnalysisTags":
        table_name = "dojo_app_analysis_tags"
        event_table_name = "dojo_app_analysis_tagsevent"
    elif model_name == "ObjectsProductTags":
        table_name = "dojo_objects_product_tags"
        event_table_name = "dojo_objects_product_tagsevent"
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

    try:
        table_name, event_table_name = get_table_names(model_name)

        table_exists, event_table_exists = check_tables_exist(table_name, event_table_name)

        if not table_exists:
            progress_callback(f"  Table {table_name} not found")
            return 0, 0.0

        if not event_table_exists:
            progress_callback(
                f"  Event table {event_table_name} not found. "
                f"Is {model_name} tracked by pghistory?",
                "DEBUG",
            )
            return 0, 0.0

        with connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            total_count = cursor.fetchone()[0]

        if total_count == 0:
            progress_callback(f"  No records found for {model_name}")
            return 0, 0.0

        progress_callback(f"  Found {total_count:,} records")

        excluded_fields = get_excluded_fields(model_name)

        with connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {event_table_name} WHERE pgh_label = 'initial_backfill'")
            existing_count = cursor.fetchone()[0]

        with connection.cursor() as cursor:
            cursor.execute(f"""
                SELECT COUNT(*) FROM {table_name} t
                WHERE NOT EXISTS (
                    SELECT 1 FROM {event_table_name} e
                    WHERE e.pgh_obj_id = t.id AND e.pgh_label = 'initial_backfill'
                )
            """)
            backfill_count = cursor.fetchone()[0]

        progress_callback(f"  Records with initial_backfill events: {existing_count:,}")
        progress_callback(f"  Records needing initial_backfill events: {backfill_count:,}")

        if backfill_count == 0:
            progress_callback(f"  ✓ All {total_count:,} records already have initial_backfill events", "SUCCESS")
            return total_count, 0.0

        if dry_run:
            progress_callback(f"  Would process {backfill_count:,} records using COPY...")
            return backfill_count, 0.0

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = %s AND column_name != 'pgh_id'
                ORDER BY ordinal_position
            """, [event_table_name])
            event_columns = [row[0] for row in cursor.fetchall()]

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

        processed = 0
        batch_start_time = time.time()
        model_start_time = time.time()

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = %s
                ORDER BY ordinal_position
            """, [table_name])
            source_columns = [row[0] for row in cursor.fetchall()]

        source_columns = [col for col in source_columns if col not in excluded_fields]

        try:
            id_column_index = source_columns.index("id")
        except ValueError:
            id_column_index = 0
            progress_callback("  Warning: 'id' column not found in source columns, using first column", "WARNING")

        consecutive_failures = 0
        max_failures = 3

        for i in range(0, len(ids_to_process), batch_size):
            batch_ids = ids_to_process[i:i + batch_size]

            if i > 0 and i % (batch_size * 10) == 0:
                progress_callback(f"  Processing batch starting at index {i:,}...")

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

            try:
                with connection.cursor() as cursor:
                    raw_cursor = cursor.cursor
                    copy_sql = f"COPY {event_table_name} ({', '.join(event_columns)}) FROM STDIN WITH (FORMAT text, DELIMITER E'\\t')"

                    records = []
                    for row in batch_rows:
                        row_data = []

                        source_values = {}
                        for idx, value in enumerate(row):
                            field_name = source_columns[idx]
                            source_values[field_name] = value

                        for col in event_columns:
                            if col == "pgh_created_at":
                                row_data.append(timezone.now())
                            elif col == "pgh_label":
                                row_data.append("initial_backfill")
                            elif col == "pgh_obj_id":
                                row_data.append(row[id_column_index] if row[id_column_index] is not None else None)
                            elif col == "pgh_context_id":
                                row_data.append(None)
                            elif col in source_values:
                                row_data.append(source_values[col])
                            else:
                                row_data.append(None)

                        records.append(tuple(row_data))

                    with raw_cursor.copy(copy_sql) as copy:
                        for record in records:
                            copy.write_row(record)
                    progress_callback("  COPY operation completed using write_row")

                    raw_cursor.connection.commit()

                    raw_cursor.execute(f"SELECT COUNT(*) FROM {event_table_name} WHERE pgh_label = 'initial_backfill'")
                    count = raw_cursor.fetchone()[0]
                    progress_callback(f"  Records in event table after batch: {count}")

                batch_processed = len(batch_rows)
                processed += batch_processed

                batch_end_time = time.time()
                batch_duration = batch_end_time - batch_start_time
                batch_records_per_second = batch_processed / batch_duration if batch_duration > 0 else 0

                progress = (processed / backfill_count) * 100
                progress_callback(
                    f"  Processed {processed:,}/{backfill_count:,} records ({progress:.1f}%) - "
                    f"Last batch: {batch_duration:.2f}s ({batch_records_per_second:.1f} records/sec)",
                )

                batch_start_time = time.time()

            except Exception as e:
                consecutive_failures += 1
                logger.error(f"Bulk insert failed for {model_name} batch: {e}")
                progress_callback(f"  Bulk insert failed: {e}", "ERROR")
                progress_callback(f"  Processed {processed:,} records before failure")

                if consecutive_failures >= max_failures:
                    progress_callback(f"  Too many consecutive failures ({consecutive_failures}), stopping processing", "ERROR")
                    break

                continue

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
        "Location", "URL",
        # Tag through tables (tagulous auto-generated)
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
