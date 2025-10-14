"""
Management command to backfill existing data into django-pghistory using COPY.

This command creates initial snapshots for all existing records in tracked models
using PostgreSQL COPY for maximum performance.
"""
import io
import logging
import time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Backfill existing data into django-pghistory using COPY"

    def add_arguments(self, parser):
        parser.add_argument(
            "--model",
            type=str,
            help='Specific model to backfill (e.g., "Finding", "Product")',
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=10000,
            help="Number of records to process in each batch (default: 10000)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without actually creating events",
        )
        parser.add_argument(
            "--log-queries",
            action="store_true",
            help="Enable database query logging (default: enabled)",
        )
        parser.add_argument(
            "--no-log-queries",
            action="store_true",
            help="Disable database query logging",
        )

    def get_excluded_fields(self, model_name):
        """Get the list of excluded fields for a specific model from pghistory configuration."""
        # Define excluded fields for each model (matching auditlog.py)
        excluded_fields_map = {
            "Dojo_User": ["password"],
            "Product": ["updated"],  # This is the key change
            "Cred_User": ["password"],
            "Notification_Webhooks": ["header_name", "header_value"],
        }
        return excluded_fields_map.get(model_name, [])

    def process_model_with_copy(self, model_name, batch_size, dry_run):
        """Process a single model using COPY operations with raw SQL."""
        try:
            # Get table names using raw SQL
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
            else:
                table_name = f"dojo_{model_name.lower()}"
                event_table_name = f"dojo_{model_name.lower()}event"

            # Check if tables exist
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

            if not table_exists:
                self.stdout.write(f"  Table {table_name} not found")
                return 0, 0.0

            if not event_table_exists:
                self.stdout.write(
                    self.style.ERROR(
                        f"  Event table {event_table_name} not found. "
                        f"Is {model_name} tracked by pghistory?",
                    ),
                )
                return 0, 0.0

            # Get total count using raw SQL
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                total_count = cursor.fetchone()[0]

            if total_count == 0:
                self.stdout.write(f"  No records found for {model_name}")
                return 0, 0.0

            self.stdout.write(f"  Found {total_count:,} records")

            # Get excluded fields
            excluded_fields = self.get_excluded_fields(model_name)

            # Check if records already have initial_import events using raw SQL
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) FROM {event_table_name} WHERE pgh_label = 'initial_import'")
                existing_count = cursor.fetchone()[0]

            # Get records that need backfill using raw SQL
            with connection.cursor() as cursor:
                cursor.execute(f"""
                    SELECT COUNT(*) FROM {table_name} t
                    WHERE NOT EXISTS (
                        SELECT 1 FROM {event_table_name} e
                        WHERE e.pgh_obj_id = t.id AND e.pgh_label = 'initial_import'
                    )
                """)
                backfill_count = cursor.fetchone()[0]

            # Log the breakdown
            self.stdout.write(f"  Records with initial_import events: {existing_count:,}")
            self.stdout.write(f"  Records needing initial_import events: {backfill_count:,}")

            if backfill_count == 0:
                self.stdout.write(
                    self.style.SUCCESS(f"  ✓ All {total_count:,} records already have initial_import events"),
                )
                return total_count, 0.0

            if dry_run:
                self.stdout.write(f"  Would process {backfill_count:,} records using COPY...")
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
                        WHERE e.pgh_obj_id = t.id AND e.pgh_label = 'initial_import'
                    )
                    ORDER BY t.id
                """)
                ids_to_process = [row[0] for row in cursor.fetchall()]

            if not ids_to_process:
                self.stdout.write("  No records need backfill")
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

            # Process in batches
            consecutive_failures = 0
            max_failures = 3

            for i in range(0, len(ids_to_process), batch_size):
                batch_ids = ids_to_process[i:i + batch_size]

                # Log progress every 10 batches
                if i > 0 and i % (batch_size * 10) == 0:
                    self.stdout.write(f"  Processing batch starting at index {i:,}...")

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
                    self.stdout.write(f"  No records found for batch at index {i}")
                    continue

                # Use PostgreSQL COPY as described in the article
                try:
                    # Prepare data for COPY using a custom file-like object
                    class FileLikeObject:
                        def __init__(self):
                            self.data = io.BytesIO()

                        def write(self, data):
                            return self.data.write(data)

                        def read(self, size=-1):
                            return self.data.read(size)

                        def seek(self, pos):
                            return self.data.seek(pos)

                        def tell(self):
                            return self.data.tell()

                        def __len__(self):
                            return len(self.data.getvalue())

                        def getvalue(self):
                            return self.data.getvalue()

                    copy_buffer = FileLikeObject()

                    for row in batch_rows:
                        row_data = []

                        # Create a mapping of source columns to values
                        source_values = {}
                        for idx, value in enumerate(row):
                            field_name = source_columns[idx]
                            # Convert value to string for COPY
                            if value is None:
                                source_values[field_name] = ""
                            elif isinstance(value, bool):
                                source_values[field_name] = "t" if value else "f"
                            elif hasattr(value, "isoformat"):  # datetime objects
                                source_values[field_name] = value.isoformat()
                            else:
                                source_values[field_name] = str(value)

                        # Build row data in the order of event_columns
                        for col in event_columns:
                            if col == "pgh_created_at":
                                row_data.append(timezone.now().isoformat())
                            elif col == "pgh_label":
                                row_data.append("initial_import")
                            elif col == "pgh_obj_id":
                                row_data.append(str(row[0]) if row[0] is not None else "")  # Assuming first column is id
                            elif col == "pgh_context_id":
                                row_data.append("")  # Empty for backfilled events
                            elif col in source_values:
                                row_data.append(source_values[col])
                            else:
                                row_data.append("")  # Default empty value

                        # Write tab-separated row to buffer as bytes
                        copy_buffer.write(("\t".join(row_data) + "\n").encode("utf-8"))

                    copy_buffer.seek(0)

                    # Debug: Show what we're about to copy
                    self.stdout.write(f"  Batch {i // batch_size + 1}: Writing to table: {event_table_name}")

                    # Use PostgreSQL COPY with psycopg3 syntax
                    with connection.cursor() as cursor:
                        # Get the underlying raw cursor to bypass Django's wrapper
                        raw_cursor = cursor.cursor
                        # Use the copy method (psycopg3 syntax)
                        copy_sql = f"COPY {event_table_name} ({', '.join(event_columns)}) FROM STDIN WITH (FORMAT text, DELIMITER E'\\t')"

                        try:
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
                                        row_data.append("initial_import")
                                    elif col == "pgh_obj_id":
                                        row_data.append(row[0])  # Assuming first column is id
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
                                self.stdout.write("  COPY operation completed using write_row")

                            # Commit the transaction to persist the data
                            raw_cursor.connection.commit()

                            # Debug: Check if data was inserted
                            raw_cursor.execute(f"SELECT COUNT(*) FROM {event_table_name} WHERE pgh_label = 'initial_import'")
                            count = raw_cursor.fetchone()[0]
                            self.stdout.write(f"  Records in event table after batch: {count}")

                        except Exception as copy_error:
                            self.stdout.write(f"  COPY error: {copy_error}")
                            # Try to get more details about the error
                            raw_cursor.execute("SELECT * FROM pg_stat_activity WHERE state = 'active'")
                            self.stdout.write(f"  Active queries: {raw_cursor.fetchall()}")
                            raise

                    batch_processed = len(batch_rows)
                    processed += batch_processed
                    consecutive_failures = 0  # Reset failure counter on success

                    # Calculate timing
                    batch_end_time = time.time()
                    batch_duration = batch_end_time - batch_start_time
                    batch_records_per_second = batch_processed / batch_duration if batch_duration > 0 else 0

                    # Log progress
                    progress = (processed / backfill_count) * 100
                    self.stdout.write(f"  Processed {processed:,}/{backfill_count:,} records ({progress:.1f}%) - "
                                    f"Last batch: {batch_duration:.2f}s ({batch_records_per_second:.1f} records/sec)")

                    batch_start_time = time.time()  # Reset for next batch

                except Exception as e:
                    consecutive_failures += 1
                    logger.error(f"Bulk insert failed for {model_name} batch: {e}")
                    self.stdout.write(f"  Bulk insert failed: {e}")
                    # Log more details about the error
                    self.stdout.write(f"  Processed {processed:,} records before failure")

                    if consecutive_failures >= max_failures:
                        self.stdout.write(f"  Too many consecutive failures ({consecutive_failures}), stopping processing")
                        break

                    # Continue with next batch instead of breaking
                    continue

            # Calculate total timing
            model_end_time = time.time()
            total_duration = model_end_time - model_start_time
            records_per_second = processed / total_duration if total_duration > 0 else 0

            self.stdout.write(
                self.style.SUCCESS(
                    f"  ✓ Completed {model_name}: {processed:,} records in {total_duration:.2f}s "
                    f"({records_per_second:.1f} records/sec)",
                ),
            )

            return processed, records_per_second  # noqa: TRY300

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"  ✗ Failed to process {model_name}: {e}"),
            )
            logger.exception(f"Error processing {model_name}")
            return 0, 0.0

    def enable_db_logging(self):
        """Enable database query logging for this command."""
        # Store original DEBUG setting
        self.original_debug = settings.DEBUG

        # Configure database query logging
        db_logger = logging.getLogger("django.db.backends")
        db_logger.setLevel(logging.DEBUG)

        # Add a handler if one doesn't exist
        if not db_logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            )
            handler.setFormatter(formatter)
            db_logger.addHandler(handler)

        # Also enable the SQL logger specifically
        sql_logger = logging.getLogger("django.db.backends.sql")
        sql_logger.setLevel(logging.DEBUG)

        # Ensure the root logger propagates to our handlers
        if not sql_logger.handlers:
            sql_logger.addHandler(handler)

        # Enable query logging in Django settings
        settings.DEBUG = True

        self.stdout.write(
            self.style.SUCCESS("Database query logging enabled"),
        )

    def disable_db_logging(self):
        """Disable database query logging."""
        # Restore original DEBUG setting
        settings.DEBUG = self.original_debug

        # Disable query logging by setting a higher level
        logging.getLogger("django.db.backends").setLevel(logging.INFO)
        logging.getLogger("django.db.backends.sql").setLevel(logging.INFO)
        self.stdout.write(
            self.style.SUCCESS("Database query logging disabled"),
        )

    def handle(self, *args, **options):
        if not settings.ENABLE_AUDITLOG or settings.AUDITLOG_TYPE != "django-pghistory":
            self.stdout.write(
                self.style.WARNING(
                    "pghistory is not enabled. Set DD_ENABLE_AUDITLOG=True and "
                    "DD_AUDITLOG_TYPE=django-pghistory",
                ),
            )
            return

        # Check if we can use COPY (PostgreSQL only)
        if settings.DATABASES["default"]["ENGINE"] != "django.db.backends.postgresql":
            self.stdout.write(
                self.style.ERROR(
                    "COPY operations only available with PostgreSQL. "
                    "Please use the original pghistory_backfill command instead.",
                ),
            )
            return

        # Enable database query logging based on options
        enable_query_logging = not options.get("no_log_queries")

        if enable_query_logging:
            self.enable_db_logging()
        else:
            self.stdout.write(
                self.style.WARNING("Database query logging disabled"),
            )

        # Models that are tracked by pghistory
        tracked_models = [
            "Dojo_User", "Endpoint", "Engagement", "Finding", "Finding_Group",
            "Product_Type", "Product", "Test", "Risk_Acceptance",
            "Finding_Template", "Cred_User", "Notification_Webhooks",
        ]

        specific_model = options.get("model")
        if specific_model:
            if specific_model not in tracked_models:
                self.stdout.write(
                    self.style.ERROR(
                        f'Model "{specific_model}" is not tracked by pghistory. '
                        f'Available models: {", ".join(tracked_models)}',
                    ),
                )
                return
            tracked_models = [specific_model]

        batch_size = options["batch_size"]
        dry_run = options["dry_run"]

        if dry_run:
            self.stdout.write(
                self.style.WARNING("DRY RUN MODE - No events will be created"),
            )

        total_processed = 0
        total_start_time = time.time()
        self.stdout.write(f"Starting backfill for {len(tracked_models)} model(s) using PostgreSQL COPY...")

        for model_name in tracked_models:
            time.time()
            self.stdout.write(f"\nProcessing {model_name}...")

            processed, _ = self.process_model_with_copy(
                model_name, batch_size, dry_run,
            )
            total_processed += processed

        # Calculate total timing
        total_end_time = time.time()
        total_duration = total_end_time - total_start_time
        total_records_per_second = total_processed / total_duration if total_duration > 0 else 0

        # Disable database query logging if it was enabled
        if enable_query_logging:
            self.disable_db_logging()

        self.stdout.write(
            self.style.SUCCESS(
                f"\nBACKFILL COMPLETE: Processed {total_processed:,} records in {total_duration:.2f}s "
                f"({total_records_per_second:.1f} records/sec)",
            ),
        )
