from django.core.management.base import BaseCommand

from dojo.tasks import run_flush_auditlog


class Command(BaseCommand):
    help = "Flush old audit log entries based on retention and batching settings"

    def add_arguments(self, parser):
        parser.add_argument("--retention-months", type=int, default=None, help="Override retention period in months")
        parser.add_argument("--batch-size", type=int, default=None, help="Override batch size")
        parser.add_argument("--max-batches", type=int, default=None, help="Override max batches per run")

    def handle(self, *args, **options):
        deleted_total, batches_done, reached_limit = run_flush_auditlog(
            retention_period=options.get("retention_months"),
            batch_size=options.get("batch_size"),
            max_batches=options.get("max_batches"),
        )
        if reached_limit:
            self.stdout.write(self.style.WARNING(
                f"Reached max batches limit; deleted {deleted_total} entries in {batches_done} batches.",
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"Deleted {deleted_total} audit log entries in {batches_done} batches.",
            ))
