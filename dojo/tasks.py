import logging
from datetime import date, datetime, time, timedelta

from auditlog.models import LogEntry
from celery.utils.log import get_task_logger
from dateutil.relativedelta import relativedelta
from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.db.models import Count, Prefetch
from django.urls import reverse
from django.utils import timezone

from dojo.celery import app
from dojo.decorators import dojo_async_task
from dojo.finding.helper import fix_loop_duplicates
from dojo.management.commands.jira_status_reconciliation import jira_status_reconciliation
from dojo.models import Alerts, Announcement, Endpoint, Engagement, Finding, Product, System_Settings, User
from dojo.notifications.helper import create_notification
from dojo.utils import calculate_grade, sla_compute_and_notify

logger = get_task_logger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


# Logs the error to the alerts table, which appears in the notification toolbar
def log_generic_alert(source, title, description):
    create_notification(event="other", title=title, description=description,
                        icon="bullseye", source=source)


@app.task(bind=True)
def add_alerts(self, runinterval):
    now = timezone.now()

    upcoming_engagements = Engagement.objects.filter(target_start__gt=now + timedelta(days=3), target_start__lt=now + timedelta(days=3) + runinterval).order_by("target_start")
    for engagement in upcoming_engagements:
        create_notification(event="upcoming_engagement",
                            title=f"Upcoming engagement: {engagement.name}",
                            engagement=engagement,
                            recipients=[engagement.lead],
                            url=reverse("view_engagement", args=(engagement.id,)))

    stale_engagements = Engagement.objects.filter(
        target_start__gt=now - runinterval,
        target_end__lt=now,
        status="In Progress").order_by("-target_end")
    for eng in stale_engagements:
        create_notification(event="stale_engagement",
                            title=f"Stale Engagement: {eng.name}",
                            description='The engagement "{}" is stale. Target end was {}.'.format(eng.name, eng.target_end.strftime("%b. %d, %Y")),
                            url=reverse("view_engagement", args=(eng.id,)),
                            recipients=[eng.lead])

    system_settings = System_Settings.objects.get()
    if system_settings.engagement_auto_close:
        # Close Engagements older than user defined days
        close_days = system_settings.engagement_auto_close_days
        unclosed_engagements = Engagement.objects.filter(target_end__lte=now - timedelta(days=close_days),
                                                        status="In Progress").order_by("target_end")

        for eng in unclosed_engagements:
            create_notification(event="auto_close_engagement",
                                title=eng.name,
                                description='The engagement "{}" has auto-closed. Target end was {}.'.format(eng.name, eng.target_end.strftime("%b. %d, %Y")),
                                url=reverse("view_engagement", args=(eng.id,)),
                                recipients=[eng.lead])

        unclosed_engagements.update(status="Completed", active=False, updated=timezone.now())

    # Calculate grade
    if system_settings.enable_product_grade:
        products = Product.objects.all()
        for product in products:
            calculate_grade(product)


@app.task(bind=True)
def cleanup_alerts(*args, **kwargs):
    try:
        max_alerts_per_user = settings.MAX_ALERTS_PER_USER
    except System_Settings.DoesNotExist:
        max_alerts_per_user = -1

    if max_alerts_per_user > -1:
        total_deleted_count = 0
        logger.info("start deleting oldest alerts if a user has more than %s alerts", max_alerts_per_user)
        users = User.objects.all()
        for user in users:
            alerts_to_delete = Alerts.objects.filter(user_id=user.id).order_by("-created")[max_alerts_per_user:].values_list("id", flat=True)
            total_deleted_count += len(alerts_to_delete)
            Alerts.objects.filter(pk__in=list(alerts_to_delete)).delete()
        logger.info("total number of alerts deleted: %s", total_deleted_count)


def run_flush_auditlog(retention_period: int | None = None,
                       batch_size: int | None = None,
                       max_batches: int | None = None) -> tuple[int, int, bool]:
    """
    Deletes audit log entries older than the configured retention period.

    Returns a tuple of (deleted_total, batches_done, reached_limit).
    """
    retention_period = retention_period if retention_period is not None else getattr(settings, "AUDITLOG_FLUSH_RETENTION_PERIOD", -1)
    if retention_period < 0:
        logger.info("Flushing auditlog is disabled")
        return 0, 0, False

    logger.info("Running Cleanup Task for Logentries with %d Months retention", retention_period)
    # Compute a datetime cutoff at start of the cutoff day to keep index-usage friendly
    retention_day = date.today() - relativedelta(months=retention_period)
    # Use a timestamp to avoid postgres having to cast to a Date field
    cutoff_dt = datetime.combine(retention_day, time.min, tzinfo=timezone.get_current_timezone())

    # Settings to control batching; sensible defaults if not configured
    batch_size = batch_size if batch_size is not None else getattr(settings, "AUDITLOG_FLUSH_BATCH_SIZE", 1000)
    max_batches = max_batches if max_batches is not None else getattr(settings, "AUDITLOG_FLUSH_MAX_BATCHES", 100)

    # Delete in batches to avoid long-running transactions and table locks
    deleted_total = 0
    batches_done = 0
    while batches_done < max_batches:
        batch_qs = LogEntry.objects.filter(timestamp__lt=cutoff_dt).order_by("pk")
        pks = list(batch_qs.values_list("pk", flat=True)[:batch_size])
        if not pks:
            if batches_done == 0:
                logger.info("No outdated Logentries found")
            break
        qs = LogEntry.objects.filter(pk__in=pks)
        deleted_count = qs._raw_delete(qs.db)
        deleted_total += int(deleted_count)
        batches_done += 1
        logger.info("Deleted batch %s (size ~%s), total deleted: %s", batches_done, batch_size, deleted_total)

    reached_limit = batches_done >= max_batches
    if reached_limit:
        logger.info("Reached max batches limit (%s). Remaining audit log entries will be deleted in the next run.", max_batches)
    else:
        logger.info("Total number of audit log entries deleted: %s", deleted_total)

    return deleted_total, batches_done, reached_limit


@app.task(bind=True)
def flush_auditlog(*args, **kwargs):
    run_flush_auditlog()


@app.task(bind=True)
def async_dupe_delete(*args, **kwargs):
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

    if enabled:
        logger.info("delete excess duplicates (max_dupes per finding: %s, max deletes per run: %s)", dupe_max, total_duplicate_delete_count_max_per_run)
        deduplicationLogger.info("delete excess duplicates (max_dupes per finding: %s, max deletes per run: %s)", dupe_max, total_duplicate_delete_count_max_per_run)

        # limit to 100 to prevent overlapping jobs
        results = Finding.objects \
                .filter(duplicate=True) \
                .order_by() \
                .values("duplicate_finding") \
                .annotate(num_dupes=Count("id")) \
                .filter(num_dupes__gt=dupe_max)[:total_duplicate_delete_count_max_per_run]

        originals_with_too_many_duplicates_ids = [result["duplicate_finding"] for result in results]

        originals_with_too_many_duplicates = Finding.objects.filter(id__in=originals_with_too_many_duplicates_ids).order_by("id")

        # prefetch to make it faster
        originals_with_too_many_duplicates = originals_with_too_many_duplicates.prefetch_related(Prefetch("original_finding",
            queryset=Finding.objects.filter(duplicate=True).order_by("date")))

        total_deleted_count = 0
        for original in originals_with_too_many_duplicates:
            duplicate_list = original.original_finding.all()
            dupe_count = len(duplicate_list) - dupe_max

            for finding in duplicate_list:
                deduplicationLogger.debug(f"deleting finding {finding.id}:{finding.title} ({finding.hash_code}))")
                finding.delete()
                total_deleted_count += 1
                dupe_count -= 1
                if dupe_count <= 0:
                    break
                if total_deleted_count >= total_duplicate_delete_count_max_per_run:
                    break

            if total_deleted_count >= total_duplicate_delete_count_max_per_run:
                break

        logger.info("total number of excess duplicates deleted: %s", total_deleted_count)


@app.task(ignore_result=False)
def celery_status():
    return True


@app.task
def async_sla_compute_and_notify_task(*args, **kwargs):
    logger.debug("Computing SLAs and notifying as needed")
    try:
        system_settings = System_Settings.objects.get()
        if system_settings.enable_finding_sla:
            sla_compute_and_notify(*args, **kwargs)
    except Exception:
        logger.exception("An unexpected error was thrown calling the SLA code")


@app.task
def jira_status_reconciliation_task(*args, **kwargs):
    return jira_status_reconciliation(*args, **kwargs)


@app.task
def fix_loop_duplicates_task(*args, **kwargs):
    return fix_loop_duplicates()


@app.task
def evaluate_pro_proposition(*args, **kwargs):
    # Ensure we should be doing this
    if not settings.CREATE_CLOUD_BANNER:
        return
    # Get the announcement object
    announcement = Announcement.objects.get_or_create(id=1)[0]
    # Quick check for a user has modified the current banner - if not, exit early as we dont want to stomp
    if not any(
        entry in announcement.message
        for entry in [
            "",
            "DefectDojo Pro Cloud and On-Premise Subscriptions Now Available!",
            "Findings/Endpoints in their systems",
        ]
    ):
        return
    # Count the objects the determine if the banner should be updated
    object_count = Finding.objects.count() + Endpoint.objects.count()
    # Unless the count is greater than 100k, exit early
    if object_count < 100000:
        return
    # Update the announcement
    announcement.message = f'Only professionals have {object_count:,} Findings and Endpoints in their systems... <a href="https://www.defectdojo.com/pricing" target="_blank">Get DefectDojo Pro</a> today!'
    announcement.save()


@app.task
def clear_sessions(*args, **kwargs):
    call_command("clearsessions")


@dojo_async_task
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
        context_manager.end()

        logger.info(f"Completed async watson index update: {instances_added} updated, {instances_skipped} skipped")

    except Exception as e:
        logger.error(f"Watson async index update failed for {model_name}: {e}")
        raise
