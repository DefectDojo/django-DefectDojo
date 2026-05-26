import logging

import pghistory
from celery import Task
from celery.utils.log import get_task_logger
from django.apps import apps
from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.core.management import call_command
from django.db.models import Count, IntegerField, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce

from dojo.auditlog import run_flush_auditlog
from dojo.celery import app
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.finding.helper import bulk_delete_findings, fix_loop_duplicates
from dojo.management.commands.jira_status_reconciliation import jira_status_reconciliation
from dojo.models import Finding, System_Settings
from dojo.utils import calculate_grade

logger = get_task_logger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


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

    # Single query: excess (oldest) duplicates, newest-first within each original group.
    # select_related avoids N+1 queries when collecting affected products below.
    # only() limits Finding columns fetched; test_id is required for the select_related join.
    excess_dupes = (
        Finding.objects
        .filter(duplicate=True, duplicate_finding__in=originals_with_excess)
        .annotate(newer_cnt=Coalesce(newer_siblings_subq, 0))
        .filter(newer_cnt__gte=dupe_max)
        .select_related("test__engagement__product")
        .only("id", "test_id")
        .order_by("id")
        [:total_duplicate_delete_count_max_per_run]
    )

    ids_to_delete = []
    affected_products = set()
    for finding in excess_dupes:
        ids_to_delete.append(finding.id)
        affected_products.add(finding.test.engagement.product)

    logger.info("total number of excess duplicates to delete: %s", len(ids_to_delete))

    if ids_to_delete:
        # order_desc=True deletes higher ids before lower ids, consistent with how
        # finding_delete handles duplicate clusters (duplicate_cluster.order_by("-id").delete()).
        bulk_delete_findings(Finding.objects.filter(id__in=ids_to_delete), order_desc=True)

    logger.info("total number of excess duplicates deleted: %s", len(ids_to_delete))

    # Batch product grading for all affected products
    if affected_products:
        system_settings = System_Settings.objects.get()
        if system_settings.enable_product_grade:
            logger.info("performing batch product grading for %s products", len(affected_products))
            for product in affected_products:
                dojo_dispatch_task(calculate_grade, product.id)


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

    logger.debug(f"Starting async watson index update for {len(pk_list)} {model_name} instances")

    try:
        # Create new SearchContextManager and start it
        context_manager = SearchContextManager()
        context_manager.start()

        # Get the default engine and model class
        engine = default_search_engine
        app_label, model_name = model_name.split(".")
        model_class = apps.get_model(app_label, model_name)

        # Bulk load instances and add them to the context
        instances = model_class.objects.filter(pk__in=pk_list)
        instances_added = 0
        instances_skipped = 0

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
