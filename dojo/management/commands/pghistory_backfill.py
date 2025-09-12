"""
Management command to backfill existing data into django-pghistory.

This command creates initial snapshots for all existing records in tracked models.
"""
import logging

from django.apps import apps
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

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

    def handle(self, *args, **options):
        if not settings.ENABLE_AUDITLOG or settings.AUDITLOG_TYPE != "django-pghistory":
            self.stdout.write(
                self.style.WARNING(
                    "pghistory is not enabled. Set DD_ENABLE_AUDITLOG=True and "
                    "DD_AUDITLOG_TYPE=django-pghistory",
                ),
            )
            return

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
        self.stdout.write(f"Starting backfill for {len(tracked_models)} model(s)...")

        for model_name in tracked_models:
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

                # Get IDs of records that already have initial_import events
                existing_initial_import_ids = set(
                    EventModel.objects.filter(pgh_label="initial_import").values_list("pgh_obj_id", flat=True),
                )

                # Filter to only get records that don't have initial_import events
                records_needing_backfill = Model.objects.exclude(id__in=existing_initial_import_ids)
                backfill_count = records_needing_backfill.count()
                existing_count = len(existing_initial_import_ids)

                # Log the breakdown
                self.stdout.write(f"  Records with initial_import events: {existing_count:,}")
                self.stdout.write(f"  Records needing initial_import events: {backfill_count:,}")

                if backfill_count == 0:
                    self.stdout.write(
                        self.style.SUCCESS(f"  ✓ All {total_count:,} records already have initial_import events"),
                    )
                    processed = total_count
                    continue

                if dry_run:
                    self.stdout.write(f"  Would process {backfill_count:,} records in batches of {batch_size:,}...")
                else:
                    self.stdout.write(f"  Processing {backfill_count:,} records in batches of {batch_size:,}...")

                # Process in batches using bulk_create
                processed = 0
                for start in range(0, backfill_count, batch_size):
                    end = min(start + batch_size, backfill_count)
                    filtered_batch = list(records_needing_backfill[start:end])

                    if not dry_run:
                        # Create events with preserved timestamps from original instances
                        event_records = []
                        for instance in filtered_batch:
                            try:
                                # Create event record with all model fields
                                event_data = {}

                                # Get excluded fields for this model from pghistory configuration
                                excluded_fields = self.get_excluded_fields(model_name)

                                # Copy all fields from the instance to event_data, except excluded ones
                                for field in instance._meta.fields:
                                    field_name = field.name
                                    if field_name not in excluded_fields:
                                        field_value = getattr(instance, field_name)
                                        event_data[field_name] = field_value

                                # Explicitly preserve created timestamp from the original instance
                                # Only if not excluded and exists
                                if hasattr(instance, "created") and instance.created and "created" not in excluded_fields:
                                    event_data["created"] = instance.created
                                # Note: We don't preserve 'updated' for Product since it's excluded

                                # Add pghistory-specific fields
                                event_data.update({
                                    "pgh_label": "initial_import",
                                    "pgh_obj": instance,  # ForeignKey to the original object
                                    "pgh_context": None,  # No context for backfilled events
                                })

                                # Set pgh_created_at to current time (this is for the event creation time)
                                # The created/updated fields above contain the original instance timestamps
                                from django.utils import timezone
                                event_data["pgh_created_at"] = timezone.now()

                                event_records.append(EventModel(**event_data))

                            except Exception as e:
                                logger.error(
                                    f"Failed to prepare event for {model_name} "
                                    f"ID {instance.id}: {e}",
                                )

                        # Bulk create all events in this batch
                        if event_records:
                            try:
                                with transaction.atomic():
                                    # Temporarily disable auto_now and auto_now_add for accurate timestamp preservation
                                    for field in EventModel._meta.fields:
                                        if hasattr(field, "auto_now"):
                                            field.auto_now = False
                                        if hasattr(field, "auto_now_add"):
                                            field.auto_now_add = False

                                    EventModel.objects.bulk_create(
                                        event_records,
                                        batch_size=batch_size,
                                    )

                                    # Restore auto_now and auto_now_add settings
                                    for field in EventModel._meta.fields:
                                        if field.name == "created" and hasattr(field, "auto_now_add"):
                                            field.auto_now_add = True
                                        if field.name == "updated" and hasattr(field, "auto_now"):
                                            field.auto_now = True
                            except Exception as e:
                                logger.error(
                                    f"Failed to bulk create events for {model_name}: {e}",
                                )
                                # Re-raise the exception instead of falling back
                                raise

                    processed += len(filtered_batch)
                    self.stdout.write(
                        f"  Processed {processed:,}/{backfill_count:,} records needing backfill "
                        f"({processed / backfill_count * 100:.1f}%)",
                    )

                total_processed += processed
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  ✓ Completed {model_name}: {processed:,} records",
                    ),
                )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"  ✗ Failed to process {model_name}: {e}"),
                )
                logger.error(f"Error processing {model_name}: {e}")

        if dry_run:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nDRY RUN COMPLETE: Would have processed {total_processed:,} records",
                ),
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nBACKFILL COMPLETE: Processed {total_processed:,} records",
                ),
            )
