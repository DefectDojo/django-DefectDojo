import logging

from django.core.management.base import BaseCommand

from dojo.models import Finding, Finding_CWE
from dojo.utils import mass_model_updater

logger = logging.getLogger(__name__)


def create_finding_cwe(finding):
    if finding.cwe and finding.cwe > 0:
        # Unique (finding, cwe) constraint makes this idempotent.
        Finding_CWE.objects.get_or_create(finding=finding, cwe=finding.cwe)


class Command(BaseCommand):

    """This management command creates Finding_CWE rows from the cwe field for all findings."""

    help = "Usage: manage.py migrate_cwe"

    def handle(self, *args, **options):

        logger.info("Starting migration of cwes for Findings")
        findings = Finding.objects.filter(cwe__gt=0)
        mass_model_updater(
            Finding,
            findings,
            create_finding_cwe,
            fields=None,
            page_size=100,
            log_prefix="creating finding cwes: ",
        )
