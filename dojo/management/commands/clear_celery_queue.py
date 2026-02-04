import logging

from django.core.management.base import BaseCommand

from dojo.celery import app

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Clear (purge) all tasks from Celery queues"

    def add_arguments(self, parser):
        parser.add_argument(
            "--queue",
            type=str,
            help="Specific queue name to clear (default: all queues)",
        )
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

    def handle(self, *args, **options):
        queue_name = options["queue"]
        dry_run = options["dry_run"]
        force = options["force"]

        # Get connection to broker
        with app.connection() as conn:
            # Get all queues or specific queue
            if queue_name:
                queues = [queue_name]
                self.stdout.write(f"Targeting queue: {queue_name}")
            else:
                # Get all active queues from the broker
                inspector = app.control.inspect()
                active_queues = inspector.active_queues()
                if active_queues:
                    # Extract unique queue names from all workers
                    queues = set()
                    for worker_queues in active_queues.values():
                        queues.update(queue_info["name"] for queue_info in worker_queues)
                    queues = list(queues)
                else:
                    # Fallback: try common default queue
                    queues = ["celery"]
                self.stdout.write(f"Found {len(queues)} queue(s) to process")

            if not queues:
                self.stdout.write(self.style.WARNING("No queues found to clear"))
                return

            # Show what will be cleared
            total_purged = 0
            for queue in queues:
                try:
                    # Get queue length using channel
                    with conn.channel() as channel:
                        _, message_count, _ = channel.queue_declare(queue=queue, passive=True)
                except Exception as e:
                    logger.debug(f"Could not get message count for queue {queue}: {e}")
                    message_count = "unknown"

                if dry_run:
                    self.stdout.write(
                        self.style.WARNING(f"  Would purge {message_count} messages from queue: {queue}"),
                    )
                else:
                    self.stdout.write(f"  Queue '{queue}': {message_count} messages")

            if dry_run:
                self.stdout.write(self.style.SUCCESS("\nDry run complete. Use without --dry-run to actually purge."))
                return

            # Confirmation prompt
            if not force:
                self.stdout.write(
                    self.style.WARNING(
                        f"\nThis will permanently delete all messages from {len(queues)} queue(s).",
                    ),
                )
                confirm = input("Are you sure you want to continue? (yes/no): ")
                if confirm.lower() not in {"yes", "y"}:
                    self.stdout.write(self.style.ERROR("Operation cancelled."))
                    return

            # Purge queues using direct channel purge
            self.stdout.write("\nPurging queues...")
            for queue in queues:
                try:
                    with conn.channel() as channel:
                        purged_count = channel.queue_purge(queue=queue)
                        total_purged += purged_count
                        self.stdout.write(
                            self.style.SUCCESS(f"  ✓ Purged {purged_count} messages from queue: {queue}"),
                        )
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"  ✗ Failed to purge queue '{queue}': {e}"),
                    )
                    logger.error(f"Error purging queue {queue}: {e}")

            if total_purged > 0:
                self.stdout.write(
                    self.style.SUCCESS(f"\nSuccessfully purged {total_purged} message(s) from {len(queues)} queue(s)."),
                )
            else:
                self.stdout.write(self.style.WARNING("\nNo messages were purged (queues may have been empty)."))
