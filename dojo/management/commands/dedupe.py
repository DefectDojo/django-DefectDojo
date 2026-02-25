import argparse
import logging

import pghistory
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Prefetch

from dojo.finding.deduplication import (
    dedupe_batch_of_findings,
    do_dedupe_batch_task,
    do_dedupe_finding_task,
    do_dedupe_finding_task_internal,
    get_finding_models_for_deduplication,
)
from dojo.models import Finding, Product
from dojo.utils import (
    calculate_grade,
    get_system_setting,
    mass_model_updater,
)

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def generate_hash_code(f):
    old_hash_code = f.hash_code
    f.hash_code = f.compute_hash_code()
    if f.hash_code != old_hash_code:
        logger.debug("%d: hash_code changed from %s to %s", f.id, old_hash_code, f.hash_code)
    return f


class Command(BaseCommand):

    """
    Updates hash codes and/or runs deduplication for findings. Hashcode calculation always runs in the foreground, dedupe by default runs in the background in batch mode.
    Usage: manage.py dedupe [--parser "Parser1 Scan" --parser "Parser2 Scan"...] [--hash_code_only] [--dedupe_only] [--dedupe_sync] [--dedupe_batch_mode]'
    """

    help = 'Usage: manage.py dedupe [--parser "Parser1 Scan" --parser "Parser2 Scan"...] [--hash_code_only] [--dedupe_only] [--dedupe_sync] [--dedupe_batch_mode]'

    def add_arguments(self, parser):
        parser.add_argument(
            "--parser",
            dest="parser",
            action="append",
            help="""List of parsers for which hash_code needs recomputing (defaults to all parsers)""",
        )

        parser.add_argument("--hash_code_only", action="store_true", help="Only compute hash codes")
        parser.add_argument("--dedupe_only", action="store_true", help="Only run deduplication")
        parser.add_argument("--dedupe_sync", action="store_true", help="Run dedupe in the foreground, default false")
        parser.add_argument(
            "--dedupe_batch_mode",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="Deduplicate in batches (similar to import), works with both sync and async modes (default: True)",
        )

    def handle(self, *args, **options):
        restrict_to_parsers = options["parser"]
        hash_code_only = options["hash_code_only"]
        dedupe_only = options["dedupe_only"]
        dedupe_sync = options["dedupe_sync"]
        dedupe_batch_mode = options.get("dedupe_batch_mode", True)  # Default to True (batch mode enabled)

        # Wrap with pghistory context for audit trail
        with pghistory.context(
            source="dedupe_command",
            dedupe_sync=dedupe_sync,
        ):
            self._run_dedupe(
                restrict_to_parsers=restrict_to_parsers,
                hash_code_only=hash_code_only,
                dedupe_only=dedupe_only,
                dedupe_sync=dedupe_sync,
                dedupe_batch_mode=dedupe_batch_mode,
            )

    def _run_dedupe(self, *, restrict_to_parsers, hash_code_only, dedupe_only, dedupe_sync, dedupe_batch_mode):
        """Internal method to run the dedupe logic within pghistory context."""
        if restrict_to_parsers is not None:
            findings = Finding.objects.filter(test__test_type__name__in=restrict_to_parsers).exclude(duplicate=True)
            logger.info("######## Will process only parsers %s and %d findings ########", *restrict_to_parsers, findings.count())
        else:
            # add filter on id to make counts not slow on mysql
            # exclude duplicates to avoid reprocessing findings that are already marked as duplicates
            findings = Finding.objects.all().filter(id__gt=0).exclude(duplicate=True)
            logger.info("######## Will process the full database with %d findings ########", findings.count())

        if settings.V3_FEATURE_LOCATIONS:
            # Prefetch related objects for synchronous deduplication
            findings = findings.select_related(
                "test", "test__engagement", "test__engagement__product", "test__test_type",
            ).prefetch_related(
                "locations",
                Prefetch(
                    "original_finding",
                    queryset=Finding.objects.only("id", "duplicate_finding_id").order_by("-id"),
                ),
            )
        else:
            # TODO: Delete this after the move to Locations
            # Prefetch related objects for synchronous deduplication
            findings = findings.select_related(
                "test", "test__engagement", "test__engagement__product", "test__test_type",
            ).prefetch_related(
                "endpoints",
                Prefetch(
                    "original_finding",
                    queryset=Finding.objects.only("id", "duplicate_finding_id").order_by("-id"),
                ),
            )

        # Phase 1: update hash_codes without deduplicating
        if not dedupe_only:
            logger.info("######## Start Updating Hashcodes (foreground) ########")

            mass_model_updater(Finding, findings, generate_hash_code, fields=["hash_code"], order="asc", log_prefix="hash_code computation ")

            logger.info("######## Done Updating Hashcodes########")

        # Phase 2: deduplicate synchronously
        if not hash_code_only:
            if get_system_setting("enable_deduplication"):
                logger.info("######## Start deduplicating (%s) ########", ("foreground" if dedupe_sync else "background"))
                if dedupe_batch_mode:
                    self._dedupe_batch_mode(findings, dedupe_sync=dedupe_sync)
                elif dedupe_sync:
                    mass_model_updater(Finding, findings, do_dedupe_finding_task_internal, fields=None, order="desc", page_size=100, log_prefix="deduplicating ")
                else:
                    # async tasks only need the id; clear select/prefetch_related to avoid
                    # FieldError when combining only("id") with select_related traversal
                    from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import

                    mass_model_updater(
                        Finding,
                        findings.select_related(None).prefetch_related(None).only("id"),
                        lambda f: dojo_dispatch_task(do_dedupe_finding_task, f.id),
                        fields=None,
                        order="desc",
                        log_prefix="deduplicating ",
                    )

                if dedupe_sync:
                    # update the grading (if enabled) and only useful in sync mode
                    # in async mode the background task that grades products every hour will pick it up
                    logger.debug("Updating grades for products...")
                    for product in Product.objects.all():
                        from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import

                        dojo_dispatch_task(calculate_grade, product.id)

                logger.info("######## Done deduplicating (%s) ########", ("foreground" if dedupe_sync else "tasks submitted to celery"))
            else:
                logger.debug("skipping dedupe because it's disabled in system settings")

    def _dedupe_batch_mode(self, findings_queryset, *, dedupe_sync: bool = True):
        """
        Deduplicate findings in batches of max 1000 per test (similar to import process).
        This is more efficient than processing findings one-by-one.
        Can run synchronously or asynchronously.
        """
        mode_str = "synchronous" if dedupe_sync else "asynchronous"
        logger.info(f"######## Deduplicating in batch mode ({mode_str}) ########")

        batch_max_size = getattr(settings, "IMPORT_REIMPORT_DEDUPE_BATCH_SIZE", 1000)
        total_findings = findings_queryset.count()
        logger.info(f"Processing {total_findings} findings in batches of max {batch_max_size} per test ({mode_str})")

        # Group findings by test_id to process them in batches per test
        test_ids = findings_queryset.values_list("test_id", flat=True).distinct()
        total_tests = len(test_ids)
        total_processed = 0

        for test_id in test_ids:
            # Get finding IDs for this test (exclude duplicates to avoid reprocessing)
            test_finding_ids = list(findings_queryset.filter(test_id=test_id).exclude(duplicate=True).values_list("id", flat=True))

            if not test_finding_ids:
                continue

            # Process findings for this test in batches of max batch_max_size
            batch_finding_ids = []
            for idx, finding_id in enumerate(test_finding_ids):
                is_final_finding_for_test = idx == len(test_finding_ids) - 1
                batch_finding_ids.append(finding_id)

                # If batch is full or we're at the end of this test's findings, process the batch
                if len(batch_finding_ids) >= batch_max_size or is_final_finding_for_test:
                    if dedupe_sync:
                        # Synchronous: load findings and process immediately
                        batch_findings = get_finding_models_for_deduplication(batch_finding_ids)
                        logger.debug(f"Deduplicating batch of {len(batch_findings)} findings for test {test_id}")
                        dedupe_batch_of_findings(batch_findings)
                    else:
                        # Asynchronous: submit task with finding IDs
                        logger.debug(f"Submitting async batch task for {len(batch_finding_ids)} findings for test {test_id}")
                        from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import

                        dojo_dispatch_task(do_dedupe_batch_task, batch_finding_ids)

                    total_processed += len(batch_finding_ids)
                    batch_finding_ids = []

            if total_processed % (batch_max_size * 10) == 0:
                logger.info(f"Processed {total_processed}/{total_findings} findings")

        logger.info(f"######## Completed batch deduplication for {total_processed} findings across {total_tests} tests ({mode_str}) ########")
