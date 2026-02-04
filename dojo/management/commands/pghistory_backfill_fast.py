"""
Management command to backfill existing data into django-pghistory using COPY.

This command creates initial snapshots for all existing records in tracked models
using PostgreSQL COPY for maximum performance.
"""
import logging
import time

from django.conf import settings
from django.core.management.base import BaseCommand

from dojo.auditlog import (
    get_tracked_models,
    process_model_backfill,
)

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
            help="Enable database query logging (default: disabled)",
        )

    def process_model_with_copy(self, model_name, batch_size, dry_run):
        """Process a single model using COPY operations with raw SQL."""
        def progress_callback(msg, style=None):
            """Progress callback that uses self.stdout.write with styling."""
            if style == "SUCCESS":
                self.stdout.write(self.style.SUCCESS(msg))
            elif style == "ERROR":
                self.stdout.write(self.style.ERROR(msg))
            elif style == "WARNING":
                self.stdout.write(self.style.WARNING(msg))
            else:
                self.stdout.write(msg)

        return process_model_backfill(
            model_name=model_name,
            batch_size=batch_size,
            dry_run=dry_run,
            progress_callback=progress_callback,
        )

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
        enable_query_logging = options.get("log_queries")

        if enable_query_logging:
            self.enable_db_logging()
        else:
            self.stdout.write(
                self.style.WARNING("Database query logging disabled"),
            )

        # Models that are tracked by pghistory
        tracked_models = get_tracked_models()

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
