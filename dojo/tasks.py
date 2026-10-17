import logging
from datetime import timedelta
from itertools import batched

import pghistory
from celery import Task
from celery.utils.log import get_task_logger
from django.apps import apps
from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.core.management import call_command
from django.db import transaction
from django.db.models import Count, IntegerField, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce
from django.utils import timezone

from dojo.auditlog import run_flush_auditlog
from dojo.celery import app
from dojo.finding.helper import bulk_delete_findings, fix_loop_duplicates
from dojo.importers.import_lock import tests_under_import_now, tests_with_import_lock_held
from dojo.management.commands.jira_status_reconciliation import jira_status_reconciliation
from dojo.models import Finding, System_Settings
from dojo.utils import schedule_product_grade

logger = get_task_logger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

# Findings locked and re-checked per transaction by _delete_excess_duplicates.
DUPE_DELETE_CHUNK_SIZE = 1000


from dojo.notifications.tasks import (  # noqa: E402, F401  -- backward compat
    add_alerts,
    cleanup_alerts,
    log_generic_alert,
)


@app.task(bind=True)
def flush_auditlog(*args, **kwargs):
    run_flush_auditlog()


@app.task(bind=True)
def async_dupe_delete(*args, **kwargs):
    # Wrap with pghistory context for audit trail
    with pghistory.context(source="dupe_delete_task"):
        _async_dupe_delete_impl()


def _async_dupe_delete_impl():
    """Internal implementation of async_dupe_delete within pghistory context."""
    try:
        system_settings = System_Settings.objects.get()
        enabled = system_settings.delete_duplicates
        dupe_max = system_settings.max_dupes
        total_duplicate_delete_count_max_per_run = settings.DUPE_DELETE_MAX_PER_RUN
    except System_Settings.DoesNotExist:
        enabled = False

    if enabled and dupe_max is None:
        logger.info("skipping deletion of excess duplicates: max_dupes not configured")
        return

    if not enabled:
        return

    logger.info("delete excess duplicates (max_dupes per finding: %s, max deletes per run: %s)", dupe_max, total_duplicate_delete_count_max_per_run)
    deduplicationLogger.info("delete excess duplicates (max_dupes per finding: %s, max deletes per run: %s)", dupe_max, total_duplicate_delete_count_max_per_run)

    # Originals that currently have more duplicates than dupe_max allows.
    originals_with_excess = (
        Finding.objects
        .filter(duplicate=True)
        .order_by()
        .values("duplicate_finding")
        .annotate(num_dupes=Count("id"))
        .filter(num_dupes__gt=dupe_max)
        .values("duplicate_finding")
    )

    # For each candidate duplicate, count siblings of the same original that are strictly newer
    # (later date, or same date but higher id — matches the keep-newest ordering).
    # A finding is excess when >= dupe_max newer siblings exist: it falls outside the kept window.
    # Coalesce(..., 0) handles the no-newer-siblings case (subquery returns NULL via empty GROUP BY).
    newer_siblings_subq = Subquery(
        Finding.objects
        .filter(
            duplicate=True,
            duplicate_finding_id=OuterRef("duplicate_finding_id"),
        )
        .filter(
            Q(date__gt=OuterRef("date")) | Q(date=OuterRef("date"), id__gt=OuterRef("id")),
        )
        .order_by()
        .values("duplicate_finding_id")
        .annotate(cnt=Count("id"))
        .values("cnt"),
        output_field=IntegerField(),
    )

    # A finding is still being written for a while after deduplication marks it duplicate: the
    # import or the create request that produced or matched it goes on to write its child rows
    # (found_by, cwe, tags, locations, vulnerability ids, companions). Those FKs are DEFERRABLE
    # INITIALLY DEFERRED, so the writer takes no lock on the finding that a delete would wait
    # for; it only fails at its COMMIT, losing the whole import. So a duplicate is a candidate
    # only once it has settled: the finding has not been saved for the grace period. An import
    # also holds a lock on its test for as long as it runs, and the delete skips that test's
    # duplicates until it ends (see dojo.importers.import_lock).
    settled = _settled_duplicates()
    # Leave the tests under import out of the selection too, before the per-run cap applies: their
    # duplicates would only be skipped below, and enough of them would use up every run.
    if busy_tests := tests_with_import_lock_held():
        settled &= ~Q(test_id__in=busy_tests)

    # Single query: excess (oldest) duplicates, newest-first within each original group.
    # select_related avoids N+1 queries when collecting affected products below.
    # only() limits Finding columns fetched; test_id is required for the select_related join.
    excess_dupes = (
        Finding.objects
        .filter(settled, duplicate=True, duplicate_finding__in=originals_with_excess)
        .annotate(newer_cnt=Coalesce(newer_siblings_subq, 0))
        .filter(newer_cnt__gte=dupe_max)
        .select_related("test__engagement__product")
        .only("id", "test_id")
        .order_by("id")
        [:total_duplicate_delete_count_max_per_run]
    )

    product_by_finding = {finding.id: finding.test.engagement.product for finding in excess_dupes}
    ids_to_delete = list(product_by_finding)

    logger.info("total number of excess duplicates to delete: %s", len(ids_to_delete))

    # Inbound duplicate_finding references from surviving findings are resolved inside
    # each chunk's transaction by bulk_delete_findings itself -- see
    # resolve_inbound_duplicate_references.
    # order_desc=True deletes higher ids before lower ids, consistent with how
    # finding_delete handles duplicate clusters (duplicate_cluster.order_by("-id").delete()).
    deleted_ids = _delete_excess_duplicates(ids_to_delete)

    logger.info("total number of excess duplicates deleted: %s", len(deleted_ids))

    # Grade only the products that lost a duplicate: a skipped one changed nothing.
    affected_products = {product_by_finding[finding_id] for finding_id in deleted_ids}

    # Batch product grading for all affected products
    if affected_products:
        system_settings = System_Settings.objects.get()
        if system_settings.enable_product_grade:
            logger.info("performing batch product grading for %s products", len(affected_products))
            for product in affected_products:
                schedule_product_grade(product.id)


def _settled_duplicates():
    """The duplicates that have not been saved for the grace period, as a Q on Finding."""
    if (grace_minutes := settings.DUPE_DELETE_GRACE_MINUTES) <= 0:
        return Q()
    cutoff = timezone.now() - timedelta(minutes=grace_minutes)
    return Q(updated__lt=cutoff) | Q(updated__isnull=True)


def _delete_excess_duplicates(ids_to_delete):
    """
    Delete the selected duplicates, except those an import is writing or a save has just touched.

    The selection ran without locks, so each chunk checks again inside its transaction. It first
    takes the import lock on the chunk's tests that are free (tests_under_import_now), which never
    waits; an import that starts on one of them now waits for the chunk to commit, when these rows
    are gone and cannot be matched. Only then does it row-lock findings, and only those of the free
    tests, so a test under import has none of its rows locked by the delete and its import never
    waits on it. A finding saved since the selection is left for a later run too.

    Returns the ids of the findings deleted.
    """
    deleted_ids = []
    for chunk in batched(sorted(ids_to_delete), DUPE_DELETE_CHUNK_SIZE, strict=False):
        with transaction.atomic():
            test_by_finding = dict(Finding.objects.filter(id__in=chunk).values_list("id", "test_id"))
            busy_tests = tests_under_import_now(set(test_by_finding.values()))
            free = [finding_id for finding_id, test_id in test_by_finding.items() if test_id not in busy_tests]
            candidates = Finding.objects.filter(id__in=free)
            if settings.DUPE_DELETE_GRACE_MINUTES > 0:
                candidates = candidates.filter(_settled_duplicates())
            still_settled = list(candidates.order_by("id").select_for_update().values_list("id", flat=True)) if free else []
            if skipped := len(chunk) - len(still_settled):
                logger.info("skipping %s excess duplicates that an import is writing, or that were saved or deleted since they were selected", skipped)
            if still_settled:
                bulk_delete_findings(Finding.objects.filter(id__in=still_settled), order_desc=True)
                deleted_ids.extend(still_settled)
    return deleted_ids


@app.task(ignore_result=False, base=Task)
def celery_status():
    """
    Simple health check task to verify Celery is running.

    Uses base Task class (not PgHistoryTask) since it doesn't need:
    - User context tracking
    - Pghistory context (no database modifications)
    """
    return True


from dojo.notifications.tasks import async_sla_compute_and_notify_task  # noqa: E402, F401  -- backward compat


@app.task
def jira_status_reconciliation_task(*args, **kwargs):
    if jira_status_reconciliation is None:
        logger.warning("Jira status reconciliation is not available")
        return None
    # Wrap with pghistory context for audit trail
    with pghistory.context(
        source="jira_reconciliation",
        mode=kwargs.get("mode", "reconcile"),
    ):
        return jira_status_reconciliation(*args, **kwargs)


@app.task
def fix_loop_duplicates_task(*args, **kwargs):
    # Wrap with pghistory context for audit trail
    with pghistory.context(source="fix_loop_duplicates"):
        return fix_loop_duplicates()


@app.task
def clear_sessions(*args, **kwargs):
    call_command("clearsessions")


@app.task
def update_watson_search_index_for_model(model_name, pk_list, *args, **kwargs):
    """
    Async task to update watson search indexes for a specific model type.

    Args:
        model_key: Model identifier like 'dojo.finding'
        pk_list: List of primary keys for instances of this model type. it's advised to chunk the list into batches of 1000 or less.

    """
    from watson.search import SearchContextManager, default_search_engine  # noqa: PLC0415 circular import

    from dojo.utils_watson_prefetch import build_indexing_queryset  # noqa: PLC0415 circular import

    logger.debug(f"Starting async watson index update for {len(pk_list)} {model_name} instances")

    try:
        # Create new SearchContextManager and start it
        context_manager = SearchContextManager()
        context_manager.start()

        # Get the default engine and model class
        engine = default_search_engine
        app_label, model_name = model_name.split(".")
        model_class = apps.get_model(app_label, model_name)

        # Bulk load instances and add them to the context. The queryset auto-derives
        # select_related/prefetch_related from the adapter's fields/store paths to
        # avoid N+1 queries during indexing. Disable via DD_WATSON_INDEX_PREFETCH_ENABLED=False.
        adapter = engine.get_adapter(model_class)
        instances = build_indexing_queryset(model_class, pk_list, adapter)
        instances_added = 0
        instances_skipped = 0

        # This task IS the terminal drain: it accumulates one already-bounded batch (<= 1000
        # PKs) into its own local SearchContextManager and bulk-saves it once via end(). The
        # intermediate size-flush hook is bound to the global singleton instance only, so
        # this private context keeps the stock add_to_context, never re-triggers the flush,
        # and cannot re-dispatch itself.
        for instance in instances:
            try:
                # Add to watson context (this will trigger indexing on end())
                context_manager.add_to_context(engine, instance)
                instances_added += 1
            except Exception as e:
                logger.warning(f"Skipping {model_name}:{instance.pk} - {e}")
                instances_skipped += 1
                continue

        # Let watson handle the bulk indexing
        try:
            context_manager.end()
        except SuspiciousOperation:
            # Some finding content (e.g. a very long tag-like string) triggered
            # Django's strip_tags SuspiciousOperation guard.  Fall back to
            # per-instance indexing so we can skip the offending object(s)
            # instead of silently dropping the entire batch.
            # https://www.djangoproject.com/weblog/2025/may/07/security-releases/
            # https://github.com/DefectDojo/django-DefectDojo/issues/14649
            logger.warning(
                f"Batch watson index update for {model_name} hit SuspiciousOperation; "
                "falling back to per-instance indexing",
            )
            instances_added = 0
            instances_skipped = 0
            for instance in instances:
                single_ctx = SearchContextManager()
                single_ctx.start()
                try:
                    single_ctx.add_to_context(engine, instance)
                    single_ctx.end()
                    instances_added += 1
                except SuspiciousOperation:
                    logger.warning(
                        f"Skipping watson index update for {model_name}:{instance.pk} "
                        "— content triggered SuspiciousOperation in strip_tags",
                    )
                    instances_skipped += 1
                except Exception as e:
                    logger.warning(f"Skipping watson index update for {model_name}:{instance.pk} - {e}")
                    instances_skipped += 1

        logger.debug(f"Completed async watson index update: {instances_added} updated, {instances_skipped} skipped")

    except Exception as e:
        logger.error(f"Watson async index update failed for {model_name}: {e}")
        raise
