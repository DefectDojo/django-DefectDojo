import logging

from django.core.management.base import BaseCommand

from dojo.finding.cwe import cwe_label
from dojo.models import Finding, Finding_CWE

logger = logging.getLogger(__name__)

BATCH_SIZE = 1000


class Command(BaseCommand):

    """Create Finding_CWE rows (canonical CWE-<n>) from the legacy Finding.cwe field for all findings."""

    help = "Usage: manage.py migrate_cwe"

    def handle(self, *args, **options):
        logger.info("Starting migration of cwes for Findings")
        findings = Finding.objects.filter(cwe__gt=0).only("id", "cwe")
        batch = []
        created = 0
        for finding in findings.iterator(chunk_size=BATCH_SIZE):
            label = cwe_label(finding.cwe)
            if label is None:
                continue
            batch.append(Finding_CWE(finding_id=finding.id, cwe=label))
            if len(batch) >= BATCH_SIZE:
                # The unique (finding, cwe) constraint makes bulk_create idempotent.
                Finding_CWE.objects.bulk_create(batch, batch_size=BATCH_SIZE, ignore_conflicts=True)
                created += len(batch)
                batch = []
        if batch:
            Finding_CWE.objects.bulk_create(batch, batch_size=BATCH_SIZE, ignore_conflicts=True)
            created += len(batch)
        logger.info("Finished migration of cwes for Findings: processed %d rows", created)
