"""
Management command to backfill existing data into django-pghistory.

This command creates initial snapshots for all existing records in tracked models.
"""
import logging
import time

from django.apps import apps
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Backfill existing data into django-pghistory"

    def add_arguments(self, parser):
        parser.add_argument(
            "--model",
            type=str,
            help='Specific model to backfill (e.g., "Finding", "Product")',
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of records to process in each batch (default: 1000)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without actually creating events",
        )
        parser.add_argument(
            "--log-queries",
            action="store_true",
            help="Enable database query logging (default: disabled)",
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

    def process_batch(self, event_model, event_records, model_name, dry_run, batch_start_time, processed, backfill_count, *, is_final_batch=False):
        """Process a batch of event records by bulk creating them in the database."""
        if not event_records:
            return 0, batch_start_time

        if dry_run:
            actually_created = len(event_records)
        else:
            try:
                attempted = len(event_records)
                # No need to pass batch_size since we're already batching ourselves
                created_objects = event_model.objects.bulk_create(event_records)
                actually_created = len(created_objects) if created_objects else 0

                if actually_created != attempted:
                    logger.warning(
                        f"bulk_create for {model_name}: attempted {attempted}, "
                        f"actually created {actually_created} ({attempted - actually_created} skipped)",
                    )
            except Exception:
                logger.exception(f"Failed to bulk create events for {model_name}")
                raise

        # Calculate timing after the actual database operation
        batch_end_time = time.time()
        batch_duration = batch_end_time - batch_start_time
        batch_records_per_second = len(event_records) / batch_duration if batch_duration > 0 else 0

        # Log batch timing
        if is_final_batch:
            self.stdout.write(f"  Final batch: {batch_duration:.2f}s ({batch_records_per_second:.1f} records/sec)")
        else:
            progress = (processed + actually_created) / backfill_count * 100
            self.stdout.write(f"  Processed {processed + actually_created:,}/{backfill_count:,} records needing backfill ({progress:.1f}%) - "
                            f"Last batch: {batch_duration:.2f}s ({batch_records_per_second:.1f} records/sec)")

        return actually_created, batch_end_time

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
        if not settings.ENABLE_AUDITLOG:
            self.stdout.write(
                self.style.WARNING(
                    "pghistory is not enabled. Set DD_ENABLE_AUDITLOG=True",
                ),
            )
            return

        # Enable database query logging based on options
        # Default to disabled unless explicitly enabled
        enable_query_logging = options.get("log_queries", False)

        if enable_query_logging:
            self.enable_db_logging()

        # Models that are tracked by pghistory
        tracked_models = [
            "Dojo_User", "Endpoint", "Engagement", "Finding", "Finding_Group",
            "Product_Type", "Product", "Test", "Risk_Acceptance",
            "Finding_Template", "Cred_User", "Notification_Webhooks",
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
        self.stdout.write(f"Starting backfill for {len(tracked_models)} model(s)...")

        for model_name in tracked_models:
            model_start_time = time.time()
            self.stdout.write(f"\nProcessing {model_name}...")

            try:
                # Get the Django model
                Model = apps.get_model("dojo", model_name)

                # Get total count
                total_count = Model.objects.count()
                if total_count == 0:
                    self.stdout.write(f"  No records found for {model_name}")
                    continue

                self.stdout.write(f"  Found {total_count:,} records")

                # Get the corresponding Event model for bulk operations
                event_table_name = f"{model_name}Event"
                try:
                    EventModel = apps.get_model("dojo", event_table_name)
                except LookupError:
                    self.stdout.write(
                        self.style.ERROR(
                            f"  Event model {event_table_name} not found. "
                            f"Is {model_name} tracked by pghistory?",
                        ),
                    )
                    continue

                # Get IDs of records that already have initial_backfill events
                existing_initial_backfill_ids = set(
                    EventModel.objects.filter(pgh_label="initial_backfill").values_list("pgh_obj_id", flat=True),
                )

                # Filter to only get records that don't have initial_backfill events
                records_needing_backfill = Model.objects.exclude(id__in=existing_initial_backfill_ids)
                backfill_count = records_needing_backfill.count()
                existing_count = len(existing_initial_backfill_ids)

                # Log the breakdown
                self.stdout.write(f"  Records with initial_backfill events: {existing_count:,}")
                self.stdout.write(f"  Records needing initial_backfill events: {backfill_count:,}")

                if backfill_count == 0:
                    self.stdout.write(
                        self.style.SUCCESS(f"  ✓ All {total_count:,} records already have initial_backfill events"),
                    )
                    processed = total_count
                    continue

                if dry_run:
                    self.stdout.write(f"  Would process {backfill_count:,} records in batches of {batch_size:,}...")
                else:
                    self.stdout.write(f"  Processing {backfill_count:,} records in batches of {batch_size:,}...")

                # Process records one by one and bulk insert every batch_size records
                processed = 0
                event_records = []
                failed_records = []
                batch_start_time = time.time()

                for instance in records_needing_backfill.iterator():
                    try:
                        # Create event record with all model fields
                        event_data = {}

                        # Get excluded fields for this model from pghistory configuration
                        excluded_fields = self.get_excluded_fields(model_name)

                        # Copy all fields from the instance to event_data, except excluded ones
                        for field in instance._meta.fields:
                            field_name = field.name
                            if field_name not in excluded_fields:
                                # Handle foreign key fields differently
                                if field.many_to_one:  # ForeignKey field
                                    # For foreign keys, use the _id field to get the raw ID value
                                    # Store it under the _id field name for the Event model
                                    field_id_name = f"{field_name}_id"
                                    field_value = getattr(instance, field_id_name)
                                    event_data[field_id_name] = field_value
                                else:
                                    # For non-foreign key fields, use value_from_object() to avoid queries
                                    field_value = field.value_from_object(instance)
                                    event_data[field_name] = field_value

                        # Explicitly preserve created timestamp from the original instance
                        # Only if not excluded and exists
                        if hasattr(instance, "created") and instance.created and "created" not in excluded_fields:
                            event_data["created"] = instance.created
                        # Note: We don't preserve 'updated' for Product since it's excluded

                        # Add pghistory-specific fields
                        event_data.update({
                            "pgh_label": "initial_backfill",
                            "pgh_obj": instance,  # ForeignKey to the original object
                            "pgh_context": None,  # No context for backfilled events
                        })

                        # Set pgh_created_at to current time (this is for the event creation time)
                        # The created/updated fields above contain the original instance timestamps
                        event_data["pgh_created_at"] = timezone.now()

                        event_records.append(EventModel(**event_data))

                    except Exception:
                        failed_records.append(instance.id)
                        logger.exception(
                            f"Failed to prepare event for {model_name} ID {instance.id}",
                        )

                    # Bulk create when we hit batch_size records
                    if len(event_records) >= batch_size:
                        # Process the batch
                        batch_processed, batch_start_time = self.process_batch(
                            EventModel, event_records, model_name, dry_run,
                            batch_start_time, processed, backfill_count,
                        )
                        processed += batch_processed

                        event_records = []  # Reset for next batch
                        batch_start_time = time.time()  # Reset batch timer

                # Handle remaining records
                if event_records:
                    # Process the final batch
                    batch_processed, _ = self.process_batch(
                        EventModel, event_records, model_name, dry_run,
                        batch_start_time, processed, backfill_count, is_final_batch=True,
                    )
                    processed += batch_processed

                # Final progress update
                if backfill_count > 0:
                    progress = (processed / backfill_count) * 100
                    self.stdout.write(f"  Processed {processed:,}/{backfill_count:,} records needing backfill ({progress:.1f}%)")

                total_processed += processed

                # Calculate timing for this model
                model_end_time = time.time()
                model_duration = model_end_time - model_start_time
                records_per_second = processed / model_duration if model_duration > 0 else 0

                # Show completion summary with timing
                if failed_records:
                    self.stdout.write(
                        self.style.WARNING(
                            f"  ⚠ Completed {model_name}: {processed:,} records processed, "
                            f"{len(failed_records)} records failed in {model_duration:.2f}s "
                            f"({records_per_second:.1f} records/sec)",
                        ),
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  ✓ Completed {model_name}: {processed:,} records in {model_duration:.2f}s "
                            f"({records_per_second:.1f} records/sec)",
                        ),
                    )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"  ✗ Failed to process {model_name}: {e}"),
                )
                logger.exception(f"Error processing {model_name}")

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
