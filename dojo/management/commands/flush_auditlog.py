from django.core.management.base import BaseCommand

from dojo.auditlog import run_flush_auditlog


class Command(BaseCommand):
    help = "Flush old audit log entries based on retention and batching settings"

    def add_arguments(self, parser):
        parser.add_argument("--retention-months", type=int, default=None, help="Override retention period in months")
        parser.add_argument("--batch-size", type=int, default=None, help="Override batch size")
        parser.add_argument("--max-batches", type=int, default=None, help="Override max batches per run")
        parser.add_argument("--dry-run", action="store_true", help="Only show how many entries would be deleted")

    def handle(self, *args, **options):
        deleted_total, batches_done, reached_limit = run_flush_auditlog(
            retention_period=options.get("retention_months"),
            batch_size=options.get("batch_size"),
            max_batches=options.get("max_batches"),
            dry_run=options.get("dry_run", False),
        )
        verb = "Would delete" if options.get("dry_run") else "Deleted"
        style = self.style.WARNING if options.get("dry_run") else self.style.SUCCESS
        suffix = " (reached max batches)" if reached_limit else ""
        self.stdout.write(style(f"{verb} {deleted_total} audit log entries in {batches_done} batches{suffix}."))
