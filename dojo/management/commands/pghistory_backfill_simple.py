import logging
import time

from django.apps import apps
from django.core.management.base import BaseCommand
from django.db import connection

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Backfill pghistory events using direct SQL INSERT - much simpler and faster!"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=10000,
            help="Number of records to process in each batch",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be processed without making changes",
        )
        parser.add_argument(
            "--models",
            nargs="+",
            help="Specific models to process (default: all configured models)",
        )

    def handle(self, *args, **options):
        batch_size = options["batch_size"]
        dry_run = options["dry_run"]
        specific_models = options.get("models")

        # Define the models to process
        models_to_process = [
            "Test",
            "Product",
            "Finding",
            "Endpoint",
            "Dojo_User",
            "Product_Type",
            "Finding_Group",
            "Risk_Acceptance",
            "Finding_Template",
            "Cred_User",
            "Notification_Webhooks",
            "FindingReviewers",  # M2M through table for Finding.reviewers
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

        if specific_models:
            models_to_process = [m for m in models_to_process if m in specific_models]

        self.stdout.write(
            self.style.SUCCESS(
                f"Starting backfill for {len(models_to_process)} model(s) using direct SQL INSERT...",
            ),
        )

        total_processed = 0
        total_start_time = time.time()

        for model_name in models_to_process:
            self.stdout.write(f"\nProcessing {model_name}...")
            processed, _records_per_second = self.process_model_simple(
                model_name, batch_size, dry_run,
            )
            total_processed += processed

        total_duration = time.time() - total_start_time
        total_records_per_second = total_processed / total_duration if total_duration > 0 else 0

        self.stdout.write(
            self.style.SUCCESS(
                f"\n✓ Backfill completed: {total_processed:,} total records in {total_duration:.2f}s "
                f"({total_records_per_second:.1f} records/sec)",
            ),
        )

    def get_excluded_fields(self, model_name):
        """Get the list of excluded fields for a specific model from pghistory configuration."""
        excluded_fields_map = {
            "Dojo_User": ["password"],
            "Product": ["updated"],
            "Cred_User": ["password"],
            "Notification_Webhooks": ["header_name", "header_value"],
        }
        return excluded_fields_map.get(model_name, [])

    def process_model_simple(self, model_name, batch_size, dry_run):
        """Process a single model using direct SQL INSERT - much simpler!"""
        try:
            # Get table names
            table_name, event_table_name = self.get_table_names(model_name)

            if not table_name or not event_table_name:
                self.stdout.write(f"  Skipping {model_name}: table not found")
                return 0, 0.0

            # Check if event table exists
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.tables
                        WHERE table_name = %s
                    )
                """, [event_table_name])
                if not cursor.fetchone()[0]:
                    self.stdout.write(f"  Skipping {model_name}: event table {event_table_name} not found")
                    return 0, 0.0

            # Get counts
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                total_count = cursor.fetchone()[0]

                cursor.execute(f"""
                    SELECT COUNT(*) FROM {table_name} t
                    WHERE NOT EXISTS (
                        SELECT 1 FROM {event_table_name} e
                        WHERE e.pgh_obj_id = t.id AND e.pgh_label = 'initial_backfill'
                    )
                """)
                backfill_count = cursor.fetchone()[0]

            if backfill_count == 0:
                self.stdout.write(f"  No records need backfill for {model_name}")
                return 0, 0.0

            self.stdout.write(f"  {backfill_count:,} records need backfill out of {total_count:,} total")

            if dry_run:
                self.stdout.write(f"  [DRY RUN] Would process {backfill_count:,} records")
                return backfill_count, 0.0

            # Get source columns (excluding pghistory-specific ones)
            excluded_fields = self.get_excluded_fields(model_name)
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = %s
                    ORDER BY ordinal_position
                """, [table_name])
                source_columns = [row[0] for row in cursor.fetchall()]

            # Filter out excluded fields
            source_columns = [col for col in source_columns if col not in excluded_fields]

            # Get event table columns (excluding pgh_id which is auto-generated)
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = %s AND column_name != 'pgh_id'
                    ORDER BY ordinal_position
                """, [event_table_name])
                event_columns = [row[0] for row in cursor.fetchall()]

            # Build the INSERT query - this is the magic!
            # We use INSERT INTO ... SELECT to directly generate the event data
            select_columns = []
            for col in event_columns:
                if col == "pgh_created_at":
                    select_columns.append("NOW() as pgh_created_at")
                elif col == "pgh_label":
                    select_columns.append("'initial_backfill' as pgh_label")
                elif col == "pgh_obj_id":
                    select_columns.append("t.id as pgh_obj_id")
                elif col == "pgh_context_id":
                    select_columns.append("NULL as pgh_context_id")
                elif col in source_columns:
                    select_columns.append(f"t.{col}")
                else:
                    select_columns.append("NULL as " + col)

            # Get all IDs that need backfill
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
                self.stdout.write("  No records need backfill")
                return 0, 0.0

            # Process in batches using direct SQL
            processed = 0
            model_start_time = time.time()

            for i in range(0, len(ids_to_process), batch_size):
                batch_ids = ids_to_process[i:i + batch_size]

                # Log progress every 10 batches
                if i > 0 and i % (batch_size * 10) == 0:
                    self.stdout.write(f"  Processing batch starting at index {i:,}...")

                # The magic happens here - direct SQL INSERT!
                insert_sql = f"""
                    INSERT INTO {event_table_name} ({', '.join(event_columns)})
                    SELECT {', '.join(select_columns)}
                    FROM {table_name} t
                    WHERE t.id = ANY(%s)
                    ORDER BY t.id
                """

                with connection.cursor() as cursor:
                    cursor.execute(insert_sql, [batch_ids])
                    batch_processed = cursor.rowcount
                    processed += batch_processed

                # Log progress every 10 batches
                if i > 0 and i % (batch_size * 10) == 0:
                    progress = (i + batch_size) / len(ids_to_process) * 100
                    self.stdout.write(f"  Processed {processed:,}/{backfill_count:,} records ({progress:.1f}%)")

            # Calculate timing
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

    def get_table_names(self, model_name):
        """Get the actual table names for a model using Django's model metadata."""
        try:
            # Get the Django model
            Model = apps.get_model("dojo", model_name)
            table_name = Model._meta.db_table

            # Get the corresponding Event model
            event_table_name = f"{model_name}Event"
            EventModel = apps.get_model("dojo", event_table_name)
            event_table_name = EventModel._meta.db_table

            return table_name, event_table_name  # noqa: TRY300
        except LookupError:
            # Model not found, return None
            return None, None
