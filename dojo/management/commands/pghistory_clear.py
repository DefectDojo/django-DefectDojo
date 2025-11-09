"""
Management command to clear all pghistory Event tables.

This command removes all historical event data from django-pghistory tables.
Use with caution as this operation is irreversible. It's meant to be used only during development/testing.
"""
import logging

from django.apps import apps
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection, transaction

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Clear all pghistory Event tables"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be cleared without actually clearing",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Skip confirmation prompt (use with caution)",
        )
        parser.add_argument(
            "--drop",
            action="store_true",
            help="Drop tables entirely instead of truncating (EXTREMELY DESTRUCTIVE)",
        )

    def handle(self, *args, **options):
        if not settings.ENABLE_AUDITLOG:
            self.stdout.write(
                self.style.WARNING(
                    "pghistory is not enabled. Set DD_ENABLE_AUDITLOG=True",
                ),
            )
            return

        # All pghistory Event tables based on tracked models
        event_tables = [
            "Cred_UserEvent",
            "Dojo_UserEvent",
            "EndpointEvent",
            "EngagementEvent",
            "Finding_GroupEvent",
            "Finding_TemplateEvent",
            "FindingEvent",
            "Notification_WebhooksEvent",
            "Product_TypeEvent",
            "ProductEvent",
            "Risk_AcceptanceEvent",
            "TestEvent",
        ]

        dry_run = options["dry_run"]
        force = options["force"]
        drop_tables = options["drop"]

        if dry_run:
            self.stdout.write(
                self.style.WARNING("DRY RUN MODE - No data will be cleared"),
            )

        total_records = 0
        table_counts = {}

        # First, count all records
        self.stdout.write("Analyzing pghistory Event tables...")
        for table_name in event_tables:
            try:
                EventModel = apps.get_model("dojo", table_name)
                count = EventModel.objects.count()
                table_counts[table_name] = count
                total_records += count

                if count > 0:
                    self.stdout.write(f"  {table_name}: {count:,} records")
                else:
                    self.stdout.write(f"  {table_name}: empty")

            except LookupError:
                self.stdout.write(
                    self.style.WARNING(f"  {table_name}: table not found (skipping)"),
                )
                continue
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"  {table_name}: error counting records - {e}"),
                )
                continue

        if total_records == 0:
            self.stdout.write(
                self.style.SUCCESS("No pghistory records found. Nothing to clear."),
            )
            return

        self.stdout.write(f"\nTotal records to clear: {total_records:,}")

        if dry_run:
            operation = "drop" if drop_tables else "clear"
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nDRY RUN COMPLETE: Would {operation} {total_records:,} records "
                    f"from {len([t for t in table_counts.values() if t > 0])} tables",
                ),
            )
            return

        # Confirmation prompt
        if not force:
            if drop_tables:
                self.stdout.write(
                    self.style.ERROR(
                        f"\n🚨 EXTREMELY DESTRUCTIVE WARNING: This will DROP {len([t for t in table_counts.values() if t > 0])} "
                        f"pghistory Event tables entirely, deleting {total_records:,} records and the table structure! "
                        "You will need to recreate tables and run migrations to restore them!",
                    ),
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f"\n⚠️  WARNING: This will permanently delete {total_records:,} "
                        "pghistory records. This operation cannot be undone!",
                    ),
                )

            operation_type = "DROP TABLES" if drop_tables else "truncate tables"
            confirm = input(f"Are you sure you want to {operation_type}? Type 'yes' to continue: ")
            if confirm.lower() != "yes":
                self.stdout.write(self.style.ERROR("Operation cancelled."))
                return

        # Clear the tables using TRUNCATE or DROP
        operation_verb = "Dropping" if drop_tables else "Truncating"
        self.stdout.write(f"\n{operation_verb} pghistory Event tables...")
        cleared_records = 0
        cleared_tables = 0

        for table_name in event_tables:
            if table_counts.get(table_name, 0) == 0:
                continue  # Skip empty tables

            try:
                EventModel = apps.get_model("dojo", table_name)

                # Use raw SQL TRUNCATE or DROP for better performance on large tables
                with transaction.atomic():
                    count = table_counts.get(table_name, 0)
                    if count > 0:
                        # Get the actual database table name
                        db_table = EventModel._meta.db_table

                        with connection.cursor() as cursor:
                            if drop_tables:
                                # DROP TABLE - completely removes the table structure
                                cursor.execute(f'DROP TABLE IF EXISTS "{db_table}" CASCADE')
                                operation_past = "Dropped"
                            else:
                                # TRUNCATE TABLE - removes all data but keeps table structure
                                cursor.execute(f'TRUNCATE TABLE "{db_table}" RESTART IDENTITY CASCADE')
                                operation_past = "Truncated"

                        cleared_records += count
                        cleared_tables += 1
                        self.stdout.write(
                            self.style.SUCCESS(f"  ✓ {operation_past} {table_name}: {count:,} records"),
                        )

            except LookupError:
                # Already handled in counting phase
                continue
            except Exception as e:
                operation_verb_lower = "drop" if drop_tables else "truncate"
                self.stdout.write(
                    self.style.ERROR(f"  ✗ Failed to {operation_verb_lower} {table_name}: {e}"),
                )
                logger.error(f"Error {operation_verb_lower}ing {table_name}: {e}")

        # Final success message
        if drop_tables:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\n🎉 DROP COMPLETE: Dropped {cleared_tables} tables with {cleared_records:,} records",
                ),
            )
            self.stdout.write(
                self.style.WARNING(
                    "⚠️  Remember to run migrations to recreate the dropped tables!",
                ),
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\n🎉 CLEARING COMPLETE: Cleared {cleared_records:,} records "
                    f"from {cleared_tables} tables",
                ),
            )
