import logging
from datetime import date, timedelta

from auditlog.models import LogEntry
from celery.utils.log import get_task_logger
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.core.management import call_command
from django.db.models import Count, Prefetch, Q
from django.urls import reverse
from django.utils import timezone
from django.core.cache import cache

from dojo.celery import app
from dojo.models import Alerts, Announcement, Endpoint, Engagement, Finding, Product, System_Settings, User, GeneralSettings
from dojo.notifications.helper import create_notification
from dojo.utils import calculate_grade, sla_compute_and_notify
from dojo.validators import resolve_persisted_tags
from dojo.azure_devops_helper import AzureDevOpsSprintHelper
from dojo.finding.prisma_images_identity import PrismaIdentityMigrationType, run_bulk_migration

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


@app.task(bind=True)
def flush_auditlog(*args, **kwargs):
    retention_period = settings.AUDITLOG_FLUSH_RETENTION_PERIOD

    if retention_period < 0:
        logger.info("Flushing auditlog is disabled")
        return

    logger.info("Running Cleanup Task for Logentries with %d Months retention", retention_period)
    retention_date = date.today() - relativedelta(months=retention_period)
    subset = LogEntry.objects.filter(timestamp__date__lt=retention_date)
    event_count = subset.count()
    logger.debug("Initially received %d Logentries", event_count)
    if event_count > 0:
        subset._raw_delete(subset.db)
        logger.debug("Total number of audit log entries deleted: %s", event_count)
    else:
        logger.debug("No outdated Logentries found")


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
    from dojo.management.commands.jira_status_reconciliation import jira_status_reconciliation
    return jira_status_reconciliation(*args, **kwargs)


@app.task
def fix_loop_duplicates_task(*args, **kwargs):
    from dojo.finding.helper import fix_loop_duplicates
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


@app.task
def bulk_migrate_prisma_ids_task(user_id, dry_run, after_engagement_id=0, batch_size=10, engagement_ids=None,
                                migration_type=PrismaIdentityMigrationType.DEPLOYMENT_CONTAINER_NAME):
    user = User.objects.get(pk=user_id)
    return run_bulk_migration(user, dry_run, after_engagement_id=after_engagement_id,
                              batch_size=batch_size, engagement_ids=engagement_ids, migration_type=migration_type)


def _get_prisma_scope_tag(finding: Finding) -> str | None:
    engagement_name = (finding.test.engagement.name or "").lower()
    impact = (finding.impact or "").lower()

    if "host" in engagement_name:
        return "hosts"
    if "sha256:" in impact:
        return "images"
    if "arn:aws:lambda" in impact:
        return "lambdas"
    return None


@app.task
def update_findings_without_tags(*args, **kwargs):
    logger.info("Starting update of findings without tags")
    findings = (
        Finding.objects.annotate(tags_count=Count("tags", distinct=True))
        .filter(
            Q(tags_count=0)
            | Q(tags_count=1, tags__name="prisma")
        )
        .distinct()
    )

    logger.info("Total findings to evaluate for without tags: %s", findings.count())

    updated_count = 0

    for finding in findings:
        finding_tags = {tag.name for tag in finding.tags.all()}
        test_tags = {tag.name for tag in finding.test.tags.all()}

        if (not finding_tags and "ciclo_escaneo" in test_tags and "Twistlock Image Scan" in finding.test.scan_type) or (
            "prisma" in finding_tags and "ciclo_escaneo" in test_tags
        ):
            scope_tag = _get_prisma_scope_tag(finding)
            if scope_tag:
                new_tags = {"prisma", scope_tag}
                if finding_tags != new_tags:
                    finding.tags.set(resolve_persisted_tags(finding.tags, sorted(new_tags)), clear=True)
                    updated_count += 1
        else:
            scan_type = (finding.test.scan_type or "").lower()
            tag_from_parser = next(
                (tag for key, tag in settings.DD_CUSTOM_TAG_PARSER.items() if key in scan_type),
                None,
            )
            if tag_from_parser:
                new_tags = {tag_from_parser}
                if finding_tags != new_tags:
                    finding.tags.set(resolve_persisted_tags(finding.tags, sorted(new_tags)), clear=True)
                    updated_count += 1

    logger.info("Completed update of findings without tags. Total updated: %s", updated_count)
    return updated_count


@app.task
def reconcile_tagulous_tag_counts(*args, **kwargs):
    """Reconcile tagulous tag counts against actual M2M table rows.

    This task compensates for the disabled synchronous count updates in
    tagulous (patched in apps.py to prevent LWLock:MultiXactOffsetSLRU /
    Lock:tuple / Lock:transactionid contention under concurrent imports).
    
    Only runs when TAGULOUS_DISABLE_SYNC_COUNT_UPDATES setting is enabled.

    For each tagged model field it:
      1. Recomputes counts from the actual M2M through table.
      2. Zeros out counts for tags no longer referenced.
      3. Deletes unprotected tags with a count of 0.
    """
    from django.db import connection
    from dojo.models import (
        App_Analysis, Endpoint, Engagement, Finding,
        Finding_Template, Objects_Product, Product, Test,
    )

    # Skip reconciliation if synchronous updates are enabled
    if not settings.TAGULOUS_DISABLE_SYNC_COUNT_UPDATES:
        logger.info("reconcile_tagulous_tag_counts: skipped (synchronous tag count updates are enabled)")
        return

    tagged_fields = [
        (Finding, "tags"),
        (Finding, "inherited_tags"),
        (Test, "tags"),
        (Test, "inherited_tags"),
        (Engagement, "tags"),
        (Engagement, "inherited_tags"),
        (Product, "tags"),
        (Endpoint, "tags"),
        (Endpoint, "inherited_tags"),
        (Finding_Template, "tags"),
        (App_Analysis, "tags"),
        (Objects_Product, "tags"),
    ]

    for model, field_name in tagged_fields:
        try:
            tag_field = model._meta.get_field(field_name)
            tag_model = tag_field.tag_model
            through_model = tag_field.remote_field.through
            tag_table = tag_model._meta.db_table
            through_table = through_model._meta.db_table

            # Locate the FK column in the through table that references the tag model
            tag_fk_col = None
            for f in through_model._meta.fields:
                if (
                    hasattr(f, "remote_field")
                    and f.remote_field is not None
                    and f.remote_field.model == tag_model
                ):
                    tag_fk_col = f.column
                    break

            if not tag_fk_col:
                logger.warning(
                    "reconcile_tagulous_tag_counts: cannot find tag FK column "
                    "for %s.%s – skipping",
                    model.__name__,
                    field_name,
                )
                continue

            with connection.cursor() as cursor:
                # 1. Set correct counts for referenced tags
                cursor.execute(
                    f"""
                    UPDATE "{tag_table}" AS t
                    SET "count" = s.cnt
                    FROM (
                        SELECT "{tag_fk_col}" AS tag_id, COUNT(*) AS cnt
                        FROM "{through_table}"
                        GROUP BY "{tag_fk_col}"
                    ) AS s
                    WHERE t.id = s.tag_id
                      AND t."count" != s.cnt
                    """
                )
                # 2. Zero out counts for tags no longer in the through table
                cursor.execute(
                    f"""
                    UPDATE "{tag_table}"
                    SET "count" = 0
                    WHERE "count" != 0
                      AND id NOT IN (
                          SELECT DISTINCT "{tag_fk_col}" FROM "{through_table}"
                      )
                    """
                )
                # 3. Remove unused non-protected tags
                cursor.execute(
                    f"""
                    DELETE FROM "{tag_table}"
                    WHERE "count" = 0 AND "protected" = FALSE
                    """
                )

            logger.info(
                "reconcile_tagulous_tag_counts: reconciled %s.%s",
                model.__name__,
                field_name,
            )
        except Exception:
            logger.exception(
                "reconcile_tagulous_tag_counts: error reconciling %s.%s",
                model.__name__,
                field_name,
            )

    logger.info("reconcile_tagulous_tag_counts: finished")


@app.task
def update_next_sprint_start_date(*args, **kwargs):
    logger.info("Starting update of next sprint start date for findings with Azure DevOps Sprint SLA")
    try:    
        if not GeneralSettings.get_value(
        "ENABLE_AZURE_DEVOPS_SPRINT_SLA_START_DATE", default=False
        ):
            logger.info("Azure DevOps sprint SLA start date update is disabled")
            return None

        # Validate configuration early
        if not all([
            settings.AZURE_DEVOPS_ORGANIZATION_URL,
            settings.AZURE_DEVOPS_OFFICES_LOCATION,
            settings.AZURE_DEVOPS_TOKEN,
        ]):
            logger.warning("Azure DevOps sprint sync enabled but missing configuration")
            return None
        
        # Cache configuration lookups to avoid repeated database calls
        test_tags = GeneralSettings.get_value("AZURE_DEVOPS_SPRINT_SLA_START_DATE_TEST_TAGS")
        if not test_tags:
            logger.warning("AZURE_DEVOPS_SPRINT_SLA_START_DATE_TEST_TAGS not configured")
            return None
        
        team = GeneralSettings.get_value("AZURE_DEVOPS_SPRINT_SLA_START_DATE_TEAM", default="Default Team")
        
        # Extract project from AZURE_DEVOPS_OFFICES_LOCATION
        # Format: "project,location1,location2,..." (team is read from GeneralSettings)
        locations = settings.AZURE_DEVOPS_OFFICES_LOCATION.split(",")
        project = locations[0].strip()
                
        helper = AzureDevOpsSprintHelper(
            organization_url=settings.AZURE_DEVOPS_ORGANIZATION_URL,
            project=project,
            team=team,
            pat=settings.AZURE_DEVOPS_TOKEN,
        )
        cache_key = "azure_devops_next_sprint_start_date"
        sprint_start_date = helper.get_next_sprint_start_date()
        if sprint_start_date is None:
            logger.warning("Failed to retrieve next sprint start date from Azure DevOps")
            return None
            
        cache.set(cache_key, sprint_start_date, 1 * 24 * 60 * 60) # Cache for 1 day
        logger.info(f"Next sprint start date updated in cache: {sprint_start_date}")

        # Use .values_list() with only needed fields and iterator() to minimize memory footprint
        # This avoids loading full Finding objects into memory unnecessarily
        max_batch_size = 1000
        findings_queryset = (
            Finding.objects
            .filter(Q(sla_start_date__isnull=True) | Q(sla_expiration_date__isnull=True))
            .filter(active=True)
            .filter(test__tags__name__in=test_tags)
            .select_related('test__engagement__product__prod_type')  # Optimize related object access
            .only('id', 'sla_start_date', 'sla_expiration_date', 'test__engagement__product__prod_type', 'tags')
            .order_by('id')
        )
        
        total_findings = findings_queryset.count()
        if total_findings == 0:
            logger.info("No findings to update with next sprint start date")
            return 0

        logger.info(f"Total findings to update with next sprint start date: {total_findings}")

        findings_to_update = []
        total_processed = 0

        # Use iterator() to stream results and reduce memory usage
        for finding in findings_queryset.iterator(chunk_size=max_batch_size):
            finding.sla_start_date = sprint_start_date
            finding.set_sla_expiration_date()
            findings_to_update.append(finding)

            if len(findings_to_update) >= max_batch_size:
                Finding.objects.bulk_update(
                    findings_to_update,
                    ["sla_start_date", "sla_expiration_date"],
                    batch_size=500,
                )
                total_processed += len(findings_to_update)
                logger.info(
                    f"Updated batch of {len(findings_to_update)} findings with sprint SLA dates "
                    f"(total: {total_processed}/{total_findings}). Progress: {(total_processed/total_findings)*100:.2f}%"
                )
                findings_to_update = []

        # Final batch
        if findings_to_update:
            Finding.objects.bulk_update(
                findings_to_update,
                ["sla_start_date", "sla_expiration_date"],
                batch_size=500,
            )
            total_processed += len(findings_to_update)

        logger.info(
            f"Finished updating {total_processed} findings with sprint SLA dates"
        )
        return total_processed
    except Exception as e:
        logger.error(f"Failed to get next sprint start date: {str(e)}")
        return None
