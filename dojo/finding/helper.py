import logging
from contextlib import suppress
from datetime import datetime
from itertools import batched
from time import strftime

from django.conf import settings
from django.db import transaction
from django.db.models.query_utils import Q
from django.db.models.signals import post_delete, pre_delete
from django.db.utils import IntegrityError
from django.dispatch.dispatcher import receiver
from django.urls import reverse
from django.utils import timezone
from django.utils.timezone import is_naive, make_aware, now
from fieldsignals import pre_save_changed

import dojo.jira_link.helper as jira_helper
import dojo.risk_acceptance.helper as ra_helper
from dojo.celery import app
from dojo.endpoint.utils import endpoint_get_or_create, save_endpoints_to_add
from dojo.file_uploads.helper import delete_related_files
from dojo.finding.deduplication import (
    dedupe_batch_of_findings,
    do_dedupe_finding_task_internal,
    do_false_positive_history,
    do_false_positive_history_batch,
    get_finding_models_for_deduplication,
)
from dojo.jira_link.helper import is_keep_in_sync_with_jira
from dojo.location.models import Location
from dojo.location.status import FindingLocationStatus
from dojo.location.utils import save_locations_to_add
from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    JIRA_Instance,
    Notes,
    System_Settings,
    Test,
    Vulnerability_Id,
)
from dojo.notes.helper import delete_related_notes
from dojo.notifications.helper import create_notification
from dojo.tools import tool_issue_updater
from dojo.url.models import URL
from dojo.utils import (
    calculate_grade,
    close_external_issue,
    get_current_user,
    get_object_or_none,
    to_str_typed,
)

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

OPEN_FINDINGS_QUERY = Q(active=True)
VERIFIED_FINDINGS_QUERY = Q(active=True, verified=True)
OUT_OF_SCOPE_FINDINGS_QUERY = Q(active=False, out_of_scope=True)
FALSE_POSITIVE_FINDINGS_QUERY = Q(active=False, duplicate=False, false_p=True)
INACTIVE_FINDINGS_QUERY = Q(active=False, duplicate=False, is_mitigated=False, false_p=False, out_of_scope=False)
ACCEPTED_FINDINGS_QUERY = Q(risk_accepted=True)
NOT_ACCEPTED_FINDINGS_QUERY = Q(risk_accepted=False)
WAS_ACCEPTED_FINDINGS_QUERY = Q(risk_acceptance__isnull=False) & Q(risk_acceptance__expiration_date_handled__isnull=False)
CLOSED_FINDINGS_QUERY = Q(is_mitigated=True)
UNDER_REVIEW_QUERY = Q(under_review=True)


# this signal is triggered just before a finding is getting saved
# and one of the status related fields has changed
# this allows us to:
# - set any depending fields such as mitigated_by, mitigated, etc.
# - update any audit log / status history
def pre_save_finding_status_change(sender, instance, changed_fields=None, **kwargs):
    # some code is cloning findings by setting id/pk to None, ignore those, will be handled on next save
    # if not instance.id:
    #     logger.debug('ignoring save of finding without id')
    #     return

    logger.debug("%i: changed status fields pre_save: %s", instance.id or 0, changed_fields)

    for field, (old, new) in changed_fields.items():
        logger.debug("%i: %s changed from %s to %s", instance.id or 0, field, old, new)
        user = None
        if get_current_user() and get_current_user().is_authenticated:
            user = get_current_user()
        update_finding_status(instance, user, changed_fields)


# also get signal when id is set/changed so we can process new findings
pre_save_changed.connect(
    pre_save_finding_status_change,
    sender=Finding,
    fields=[
        "id",
        "active",
        "verified",
        "false_p",
        "is_mitigated",
        "mitigated",
        "mitigated_by",
        "out_of_scope",
        "risk_accepted",
    ],
)


def update_finding_status(new_state_finding, user, changed_fields=None):
    now = timezone.now()

    logger.debug("changed fields: %s", changed_fields)

    is_new_finding = not changed_fields or (changed_fields and len(changed_fields) == 1 and "id" in changed_fields)

    # activated
    # reactivated
    # closed / mitigated
    # false positivized
    # out_of_scopified
    # marked as duplicate
    # marked as original

    if is_new_finding or "is_mitigated" in changed_fields:
        # finding is being mitigated
        if new_state_finding.is_mitigated:
            # when mitigating a finding, the meta fields can only be editted if allowed
            logger.debug("finding being mitigated, set mitigated and mitigated_by fields")

            if can_edit_mitigated_data(user):
                # only set if it was not already set by user
                # not sure if this check really covers all cases, but if we make it more strict
                # it will cause all kinds of issues I believe with new findings etc
                new_state_finding.mitigated = new_state_finding.mitigated or now
                new_state_finding.mitigated_by = new_state_finding.mitigated_by or user

        # finding is being "un"mitigated
        else:
            new_state_finding.mitigated = None
            new_state_finding.mitigated_by = None

    # Ensure mitigated metadata is present for mitigated findings
    # If values are provided (including custom ones), keep them; if missing, set defaults
    if new_state_finding.is_mitigated:
        if not new_state_finding.mitigated:
            new_state_finding.mitigated = now
        if not new_state_finding.mitigated_by:
            new_state_finding.mitigated_by = user

    if is_new_finding or "active" in changed_fields:
        # finding is being (re)activated
        if new_state_finding.active:
            new_state_finding.false_p = False
            new_state_finding.out_of_scope = False
            new_state_finding.is_mitigated = False
            new_state_finding.mitigated = None
            new_state_finding.mitigated_by = None
        else:
            # finding is being deactivated
            pass

    if is_new_finding or "false_p" in changed_fields or "out_of_scope" in changed_fields:
        # existing behaviour is that false_p or out_of_scope implies mitigated
        if new_state_finding.false_p or new_state_finding.out_of_scope:
            new_state_finding.mitigated = new_state_finding.mitigated or now
            new_state_finding.mitigated_by = new_state_finding.mitigated_by or user
            new_state_finding.is_mitigated = True
            new_state_finding.active = False
            new_state_finding.verified = False

    # always reset some fields if the finding is not a duplicate
    if not new_state_finding.duplicate:
        new_state_finding.duplicate = False
        new_state_finding.duplicate_finding = None

    new_state_finding.last_status_update = now


def filter_findings_by_existence(findings):
    """
    Return only findings that still exist in the database (by id).

    Centralized helper used by importers to avoid FK violations during
    bulk_create.
    """
    if not findings:
        return []
    candidate_ids = [finding.id for finding in findings if getattr(finding, "id", None)]
    if not candidate_ids:
        return []
    existing_ids = set(
        Finding.objects.filter(id__in=candidate_ids).values_list("id", flat=True),
    )
    return [finding for finding in findings if finding.id in existing_ids]


def can_edit_mitigated_data(user):
    return settings.EDITABLE_MITIGATED_DATA and user and getattr(user, "is_superuser", False)


def create_finding_group(finds, finding_group_name):
    logger.debug("creating finding_group_create")
    if not finds or len(finds) == 0:
        msg = "cannot create empty Finding Group"
        raise ValueError(msg)

    finding_group_name_dummy = "bulk group " + strftime("%a, %d %b  %Y %X", timezone.now().timetuple())

    finding_group = Finding_Group(test=finds[0].test)
    finding_group.creator = get_current_user()

    if finding_group_name:
        finding_group.name = finding_group_name[:255]
    elif finding_group.components:
        finding_group.name = finding_group.components[:255]
    try:
        finding_group.save()
    except IntegrityError as ie:
        if "already exists" in str(ie):
            finding_group.name = finding_group_name[:255 - len(finding_group_name_dummy)] + finding_group_name_dummy
            finding_group.save()
        else:
            raise

    available_findings = [find for find in finds if not find.finding_group_set.all()]
    finding_group.findings.set(available_findings)

    added = len(available_findings)
    skipped = len(finds) - added
    return finding_group, added, skipped


def add_to_finding_group(finding_group, finds):
    added = 0
    skipped = 0
    available_findings = [find for find in finds if not find.finding_group_set.all()]
    finding_group.findings.add(*available_findings)

    # Now update the JIRA to add the finding to the finding group
    jira_instance = jira_helper.get_jira_instance(finding_group)
    if finding_group.has_jira_issue and jira_instance and jira_instance.finding_jira_sync:
        logger.debug("pushing to jira from finding.finding_bulk_update_all()")
        jira_helper.push_to_jira(finding_group)

    added = len(available_findings)
    skipped = len(finds) - added
    return finding_group, added, skipped


def remove_from_finding_group(finds):
    removed = 0
    skipped = 0
    affected_groups = set()
    for find in finds:
        groups = find.finding_group_set.all()
        if not groups:
            skipped += 1
            continue

        for group in find.finding_group_set.all():
            group.findings.remove(find)
            affected_groups.add(group)

        removed += 1

    # Now update the JIRA to remove the finding from the finding group
    for group in affected_groups:
        jira_instance = jira_helper.get_jira_instance(group)
        if group.has_jira_issue and jira_instance and jira_instance.finding_jira_sync:
            logger.debug("pushing to jira from finding.finding_bulk_update_all()")
            jira_helper.push_to_jira(group)

    return affected_groups, removed, skipped


def update_finding_group(finding, finding_group):
    # finding_group = Finding_Group.objects.get(id=group)
    if finding_group is not None:
        if finding_group != finding.finding_group:
            if finding.finding_group:
                logger.debug("removing finding %d from finding_group %s", finding.id, finding.finding_group)
                finding.finding_group.findings.remove(finding)
            logger.debug("adding finding %d to finding_group %s", finding.id, finding_group)
            finding_group.findings.add(finding)
    elif finding.finding_group:
        logger.debug("removing finding %d from finding_group %s", finding.id, finding.finding_group)
        finding.finding_group.findings.remove(finding)


def get_group_by_group_name(finding, finding_group_by_option):
    group_name = None

    if finding_group_by_option == "component_name":
        group_name = finding.component_name
    elif finding_group_by_option == "component_name+component_version":
        if finding.component_name or finding.component_version:
            group_name = "{}:{}".format(finding.component_name or "None", finding.component_version or "None")
    elif finding_group_by_option == "file_path":
        if finding.file_path:
            group_name = f"Filepath {finding.file_path}"
    elif finding_group_by_option == "finding_title":
        group_name = finding.title
    elif finding_group_by_option == "vuln_id_from_tool":
        if finding.vuln_id_from_tool:
            group_name = f"Vulnerability ID {finding.vuln_id_from_tool}" if finding.vuln_id_from_tool else "None"
    else:
        msg = f"Invalid group_by option {finding_group_by_option}"
        raise ValueError(msg)
    if group_name:
        return f"Findings in: {group_name}"

    return group_name


def group_findings_by(finds, finding_group_by_option):
    grouped = 0
    groups_created = 0
    groups_existing = 0
    skipped = 0
    affected_groups = set()
    for find in finds:
        if find.finding_group is not None:
            skipped += 1
            continue

        group_name = get_group_by_group_name(find, finding_group_by_option)
        if group_name is None:
            skipped += 1
            continue

        finding_group = Finding_Group.objects.filter(test=find.test, name=group_name).first()
        if not finding_group:
            finding_group, added, skipped = create_finding_group([find], group_name)
            groups_created += 1
            grouped += added
            skipped += skipped
        else:
            add_to_finding_group(finding_group, [find])
            groups_existing += 1
            grouped += 1

        affected_groups.add(finding_group)

    # Now update the JIRA to add the finding to the finding group
    for group in affected_groups:
        jira_instance = jira_helper.get_jira_instance(group)
        if group.has_jira_issue and jira_instance and jira_instance.finding_jira_sync:
            logger.debug("pushing to jira from finding.finding_bulk_update_all()")
            jira_helper.push_to_jira(group)

    return affected_groups, grouped, skipped, groups_created


def add_findings_to_auto_group(name, findings, group_by, *, create_finding_groups_for_all_findings=True, **kwargs):
    if name is not None and findings is not None and len(findings) > 0:
        creator = get_current_user()
        test = findings[0].test

        if create_finding_groups_for_all_findings or len(findings) > 1:
            # Only create a finding group if we have more than one finding for a given finding group, unless configured otherwise
            finding_group, created = Finding_Group.objects.get_or_create(test=test, creator=creator, name=name[:255])
            if created:
                logger.debug("Created Finding Group %d:%s for test %d:%s", finding_group.id, finding_group, test.id, test)
                # See if we have old findings in the same test that were created without a finding group
                # that should be added to this new group
                old_findings = Finding.objects.filter(test=test)
                for f in old_findings:
                    f_group_name = get_group_by_group_name(f, group_by)
                    if f_group_name == name and f not in findings:
                        finding_group.findings.add(f)

            finding_group.findings.add(*findings)
        else:
            # Otherwise add to an existing finding group if it exists only
            try:
                finding_group = Finding_Group.objects.get(test=test, name=name)
                if finding_group:
                    finding_group.findings.add(*findings)
            except:
                # See if we have old findings in the same test that were created without a finding group
                # that match this new finding - then we can create a finding group
                old_findings = Finding.objects.filter(test=test)
                created = False
                for f in old_findings:
                    f_group_name = get_group_by_group_name(f, group_by)
                    if f_group_name == name and f not in findings:
                        finding_group, created = Finding_Group.objects.get_or_create(test=test, creator=creator, name=name[:255])
                        finding_group.findings.add(f)
                if created:
                    finding_group.findings.add(*findings)


@app.task
def post_process_finding_save(finding_id, dedupe_option=True, rules_option=True, product_grading_option=True,  # noqa: FBT002
             issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):  # noqa: FBT002 - this is bit hard to fix nice have this universally fixed
    finding = get_object_or_none(Finding, id=finding_id)
    if not finding:
        logger.warning("Finding with id %s does not exist, skipping post_process_finding_save", finding_id)
        return None

    return post_process_finding_save_internal(finding, dedupe_option, rules_option, product_grading_option,
                                   issue_updater_option, push_to_jira, user, *args, **kwargs)


def post_process_finding_save_internal(finding, dedupe_option=True, rules_option=True, product_grading_option=True,  # noqa: FBT002
             issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):  # noqa: FBT002 - this is bit hard to fix nice have this universally fixed

    if not finding:
        logger.warning("post_process_finding_save called with finding==None, skipping post processing")
        return

    system_settings = System_Settings.objects.get()

    # STEP 1 run all status changing tasks sequentially to avoid race conditions
    if dedupe_option:
        if finding.hash_code is not None:
            if system_settings.enable_deduplication:
                do_dedupe_finding_task_internal(finding, *args, **kwargs)
            else:
                deduplicationLogger.debug("skipping dedupe because it's disabled in system settings")
        else:
            deduplicationLogger.warning("skipping dedupe because hash_code is None")

    if system_settings.false_positive_history:
        # Only perform false positive history if deduplication is disabled
        if system_settings.enable_deduplication:
            deduplicationLogger.warning("skipping false positive history because deduplication is also enabled")
        else:
            do_false_positive_history(finding, *args, **kwargs)

    # STEP 2 run all non-status changing tasks as celery tasks in the background
    if issue_updater_option:
        tool_issue_updater.async_tool_issue_update(finding)

    if product_grading_option:
        if system_settings.enable_product_grade:
            from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import

            dojo_dispatch_task(calculate_grade, finding.test.engagement.product.id)
        else:
            deduplicationLogger.debug("skipping product grading because it's disabled in system settings")

    # Adding a snippet here for push to JIRA so that it's in one place
    if push_to_jira:
        logger.debug("pushing finding %s to jira from finding.save()", finding.pk)

        # current approach is that whenever a finding is in a group, the group will be pushed to JIRA
        # based on feedback we could introduct another push_group_to_jira boolean everywhere
        # but what about the push_all boolean? Let's see how this works for now and get some feedback.
        if finding.has_jira_issue or not finding.finding_group:
            jira_helper.push_to_jira(finding)
        elif finding.finding_group:
            jira_helper.push_to_jira(finding.finding_group)


@app.task
def post_process_findings_batch(
    finding_ids,
    *args,
    dedupe_option=True,
    rules_option=True,
    product_grading_option=True,
    issue_updater_option=True,
    push_to_jira=False,
    jira_instance_id=None,
    user=None,
    sync=False,
    **kwargs,
):

    logger.debug(
        f"post_process_findings_batch called: finding_ids_count={len(finding_ids) if finding_ids else 0}, "
        f"args={args}, dedupe_option={dedupe_option}, rules_option={rules_option}, "
        f"product_grading_option={product_grading_option}, issue_updater_option={issue_updater_option}, "
        f"push_to_jira={push_to_jira}, jira_instance_id={jira_instance_id}, user={user.id if user else None}, kwargs={kwargs}",
    )
    if not finding_ids:
        return

    system_settings = System_Settings.objects.get()

    # use list() to force a complete query execution and related objects to be loaded once
    logger.debug(f"getting finding models for batch deduplication with: {len(finding_ids)} findings")
    findings = get_finding_models_for_deduplication(finding_ids)
    logger.debug(f"found {len(findings)} findings for batch deduplication")

    if not findings:
        logger.debug(f"no findings found for batch deduplication with IDs: {finding_ids}")
        return

    # Batch dedupe with single queries per algorithm; fallback to per-finding for anything else
    if dedupe_option and system_settings.enable_deduplication:
        dedupe_batch_of_findings(findings)

    if system_settings.false_positive_history:
        # Only perform false positive history if deduplication is disabled
        if system_settings.enable_deduplication:
            deduplicationLogger.warning("skipping false positive history because deduplication is also enabled")
        else:
            do_false_positive_history_batch(findings)

    # Non-status changing tasks
    if issue_updater_option:
        for finding in findings:
            tool_issue_updater.async_tool_issue_update(finding)

    if product_grading_option and system_settings.enable_product_grade:
        from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import

        dojo_dispatch_task(calculate_grade, findings[0].test.engagement.product.id, sync=sync)

    # If we received the ID of a jira instance, then we need to determine the keep in sync behavior
    jira_instance = None
    if jira_instance_id is not None:
        with suppress(JIRA_Instance.DoesNotExist):
            jira_instance = JIRA_Instance.objects.get(id=jira_instance_id)
    # We dont check if the finding jira sync is applicable quite yet until we can get in the loop
        # but this is a way to at least make it that far
    if push_to_jira or getattr(jira_instance, "finding_jira_sync", False):
        for finding in findings:
            object_to_push = finding if finding.has_jira_issue or not finding.finding_group else finding.finding_group
            # Check the push_to_jira flag again to potentially shorty circuit without checking for existing findings
            if push_to_jira or is_keep_in_sync_with_jira(object_to_push, prefetched_jira_instance=jira_instance):
                jira_helper.push_to_jira(object_to_push)
    else:
        logger.debug("push_to_jira is False, not pushing to JIRA")


@receiver(pre_delete, sender=Finding)
def finding_pre_delete(sender, instance, **kwargs):
    logger.debug("finding pre_delete: %d", instance.id)
    # this shouldn't be necessary as Django should remove any Many-To-Many entries automatically, might be a bug in Django?
    # https://code.djangoproject.com/ticket/154
    instance.found_by.clear()
    delete_related_notes(instance)
    delete_related_files(instance)


def finding_delete(instance, **kwargs):
    logger.debug("finding delete, instance: %s", instance.id)

    # the idea is that the engagement/test pre delete already prepared all the duplicates inside
    # the test/engagement to no longer point to any original so they can be safely deleted.
    # so if we still find that the finding that is going to be delete is an original, it is either
    # a manual / single finding delete, or a bulke delete of findings
    # in which case we have to process all the duplicates
    # TODO: should we add the prepocessing also to the bulk edit form?
    logger.debug("finding_delete: refresh from db: pk: %d", instance.pk)

    try:
        instance.refresh_from_db()
    except Finding.DoesNotExist:
        # due to cascading deletes, the current finding could have been deleted already
        # but django still calls delete() in this case
        return

    duplicate_cluster = instance.original_finding.all()
    if duplicate_cluster:
        if settings.DUPLICATE_CLUSTER_CASCADE_DELETE:
            duplicate_cluster.order_by("-id").delete()
        else:
            reconfigure_duplicate_cluster(instance, duplicate_cluster)
    else:
        logger.debug("no duplicate cluster found for finding: %d, so no need to reconfigure", instance.id)

    # this shouldn't be necessary as Django should remove any Many-To-Many entries automatically, might be a bug in Django?
    # https://code.djangoproject.com/ticket/154
    logger.debug("finding delete: clearing found by")
    instance.found_by.clear()


@receiver(post_delete, sender=Finding)
def finding_post_delete(sender, instance, **kwargs):
    # Catch instances in async delete where a single object is deleted more than once
    with suppress(Finding.DoesNotExist):
        logger.debug("finding post_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))


# can't use model to id here due to the queryset
# @dojo_async_task
# @app.task
def reconfigure_duplicate_cluster(original, cluster_outside):
    # when a finding is deleted, and is an original of a duplicate cluster, we have to chose a new original for the cluster
    # only look for a new original if there is one outside this test
    if original is None or cluster_outside is None or len(cluster_outside) == 0:
        return

    if settings.DUPLICATE_CLUSTER_CASCADE_DELETE:
        # Don't delete here — the caller (async_delete_crawl_task or finding_delete)
        # handles deletion of outside-scope duplicates efficiently via bulk_delete_findings.
        return
    logger.debug("reconfigure_duplicate_cluster: cluster_outside: %s", cluster_outside)
    # set new original to first finding in cluster (ordered by id)
    new_original = cluster_outside.order_by("id").first()
    if new_original:
        logger.debug("changing original of duplicate cluster %d to: %s:%s", original.id, new_original.id, new_original.title)

        # Use .update() to avoid triggering Finding.save() signals
        Finding.objects.filter(id=new_original.id).update(
            duplicate=False,
            duplicate_finding=None,
            active=original.active,
            is_mitigated=original.is_mitigated,
        )
        new_original.found_by.set(original.found_by.all())

        # Re-point remaining duplicates to the new original in a single query
        cluster_outside.exclude(id=new_original.id).update(duplicate_finding=new_original)


def prepare_duplicates_for_delete(obj):
    """
    Prepare duplicate clusters before deleting a Test, Engagement, Product, or Product_Type.

    Resets inside-scope duplicate FKs and reconfigures outside-scope clusters
    so that cascade_delete won't hit FK violations on the self-referential
    duplicate_finding field.
    """
    from dojo.utils import FINDING_SCOPE_FILTERS  # noqa: PLC0415 circular import

    scope_field = FINDING_SCOPE_FILTERS.get(type(obj))
    if scope_field is None:
        logger.warning("prepare_duplicates_for_delete: unsupported object type %s", type(obj).__name__)
        return

    logger.debug("prepare_duplicates_for_delete: %s %d", type(obj).__name__, obj.id)

    # Build scope as a subquery — never materialized into Python memory
    scope_ids_subquery = Finding.objects.filter(**{scope_field: obj}).values_list("id", flat=True)

    # Fix any transitive duplicate loops within scope before reconfiguring clusters.
    # Scoped to the deletion set to avoid a full-table self-join on large instances.
    fix_loop_duplicates(scope_qs=Finding.objects.filter(**{scope_field: obj}))

    if not scope_ids_subquery.exists():
        logger.debug("no findings in scope, nothing to prepare")
        return

    # Bulk-reset inside-scope duplicates: single UPDATE instead of per-original mass_model_updater.
    # Clears the duplicate_finding FK so cascade_delete won't trip over dangling self-references.
    inside_reset_count = Finding.objects.filter(
        duplicate=True,
        duplicate_finding_id__in=scope_ids_subquery,
        id__in=scope_ids_subquery,
    ).update(duplicate_finding=None, duplicate=False)
    logger.debug("bulk-reset %d inside-scope duplicates", inside_reset_count)

    # Reconfigure outside-scope duplicates: still per-original because each cluster
    # needs a new original chosen, status copied, and found_by updated.
    # Chunked with prefetch_related to bound memory while avoiding N+1 queries.
    originals_ids = (
        Finding.objects.filter(
            id__in=scope_ids_subquery,
            original_finding__in=Finding.objects.exclude(id__in=scope_ids_subquery),
        )
        .distinct()
        .values_list("id", flat=True)
        .iterator(chunk_size=500)
    )

    for chunk_ids in batched(originals_ids, 500, strict=False):
        for original in Finding.objects.filter(id__in=chunk_ids).prefetch_related("original_finding"):
            # Inside-scope duplicates were already unlinked by the bulk UPDATE above,
            # so original_finding.all() now only contains outside-scope duplicates.
            reconfigure_duplicate_cluster(original, original.original_finding.all())


@receiver(pre_delete, sender=Test)
def test_pre_delete(sender, instance, **kwargs):
    logger.debug("test pre_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))
    prepare_duplicates_for_delete(instance)


@receiver(post_delete, sender=Test)
def test_post_delete(sender, instance, **kwargs):
    logger.debug("test post_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))


@receiver(pre_delete, sender=Engagement)
def engagement_pre_delete(sender, instance, **kwargs):
    logger.debug("engagement pre_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))
    prepare_duplicates_for_delete(instance)


@receiver(post_delete, sender=Engagement)
def engagement_post_delete(sender, instance, **kwargs):
    logger.debug("engagement post_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))


def bulk_clear_finding_m2m(finding_qs):
    """
    Bulk-clear M2M through tables for a queryset of findings.

    Must be called BEFORE cascade_delete since M2M through tables
    are not discovered by _meta.related_objects.

    Special handling for FileUpload: deletes via ORM so the custom
    FileUpload.delete() fires and removes files from disk storage.
    Tags are handled via bulk_remove_all_tags to maintain tag counts.
    """
    from dojo.tag_utils import bulk_remove_all_tags  # noqa: PLC0415 circular import

    finding_ids = finding_qs.values_list("id", flat=True)

    # Collect FileUpload IDs before deleting through table entries
    file_ids = list(
        Finding.files.through.objects.filter(
            finding_id__in=finding_ids,
        ).values_list("fileupload_id", flat=True),
    )

    # Collect Note IDs before deleting through table entries
    note_ids = list(
        Finding.notes.through.objects.filter(
            finding_id__in=finding_ids,
        ).values_list("notes_id", flat=True),
    )

    # Remove tags with proper count maintenance
    bulk_remove_all_tags(Finding, finding_ids)

    # Auto-discover and delete M2M through tables — both forward (Finding._meta.many_to_many)
    # and reverse (other models with ManyToManyField pointing to Finding, e.g. Finding_Group.findings).
    # Forward M2M fields use field.remote_field.through, reverse use field.through.
    m2m_through_models = set()
    for field_info in Finding._meta.get_fields():
        if hasattr(field_info, "tag_options"):
            continue
        through = getattr(field_info, "through", None) or getattr(getattr(field_info, "remote_field", None), "through", None)
        if through is not None:
            m2m_through_models.add(through)

    for through_model in m2m_through_models:
        # Find the FK column that points to Finding
        fk_column = None
        for field in through_model._meta.get_fields():
            if hasattr(field, "related_model") and field.related_model is Finding:
                fk_column = field.column
                break
        if fk_column:
            count, _ = through_model.objects.filter(
                **{f"{fk_column}__in": finding_ids},
            ).delete()
            if count:
                logger.debug(
                    "bulk_clear_finding_m2m: deleted %d rows from %s",
                    count, through_model._meta.db_table,
                )

    # Delete FileUpload objects via ORM one-by-one so the custom
    # FileUpload.delete() method fires and removes files from disk storage.
    # Bulk deletion would orphan files on disk. File attachments are uncommon
    # so the per-object overhead is negligible in practice.
    if file_ids:
        for file_upload in FileUpload.objects.filter(id__in=file_ids).iterator():
            file_upload.delete()

    # Delete orphaned Notes
    if note_ids:
        Notes.objects.filter(id__in=note_ids).delete()


def _bulk_delete_findings_internal(finding_qs, chunk_size=1000):
    """
    Delete findings and all related objects efficiently. Including any related object in Dojo-Pro

    Sends the pre_bulk_delete signal, clears M2M through tables (not
    discovered by _meta.related_objects), then uses cascade_delete for
    all FK relations via raw SQL.
    Chunked with per-chunk transaction.atomic() for crash safety.
    """
    from dojo.signals import pre_bulk_delete_findings  # noqa: PLC0415 circular import
    from dojo.utils_cascade_delete import (  # noqa: PLC0415 circular import
        cascade_delete_related_objects,
        execute_delete_sql,
    )

    pre_bulk_delete_findings.send(sender=Finding, finding_qs=finding_qs)
    bulk_clear_finding_m2m(finding_qs)
    for chunk_num, chunk_ids in enumerate(
        batched(
            finding_qs.values_list("id", flat=True).order_by("id").iterator(chunk_size=chunk_size),
            chunk_size,
            strict=False,
        ),
        start=1,
    ):
        chunk_qs = Finding.objects.filter(id__in=chunk_ids)
        with transaction.atomic():
            cascade_delete_related_objects(Finding, chunk_qs, skip_relations={Finding}, skip_m2m_for={Finding})
            execute_delete_sql(chunk_qs)
        logger.info(
            "bulk_delete_findings: deleted chunk %d (%d findings)",
            chunk_num, len(chunk_ids),
        )


def bulk_delete_findings(finding_qs, chunk_size=1000, cascade_root=None):
    """
    Entry point; may delegate to Pro via settings.BULK_DELETE_FINDINGS_METHOD.

    cascade_root: optional dict describing the top-level object whose cascade triggered
    this bulk delete (e.g. {"model": "dojo.engagement", "pk": 9}). Ignored by OSS
    when no custom method is configured.
    """
    from dojo.utils import get_custom_method  # noqa: PLC0415 circular import

    if fn := get_custom_method("BULK_DELETE_FINDINGS_METHOD"):
        return fn(finding_qs, chunk_size=chunk_size, cascade_root=cascade_root)
    return _bulk_delete_findings_internal(finding_qs, chunk_size=chunk_size)


def fix_loop_duplicates(scope_qs=None):
    """Due to bugs in the past and even currently when under high parallel load, there can be transitive duplicates."""
    """ i.e. A -> B -> C. This can lead to problems when deleting findingns, performing deduplication, etc """
    # Build base queryset without selecting full rows to minimize memory
    base_qs = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False)
    if scope_qs is not None:
        base_qs = base_qs.filter(id__in=scope_qs.values_list("id", flat=True))

    # Use COUNT(*) at the DB instead of materializing the queryset
    loop_count = base_qs.count()

    if loop_count > 0:
        deduplicationLogger.warning("fix_loop_duplicates: found %d findings with duplicate loops", loop_count)
        # Stream IDs only in descending order to avoid loading full Finding rows
        for find_id in base_qs.order_by("-id").values_list("id", flat=True).iterator(chunk_size=1000):
            deduplicationLogger.warning("fix_loop_duplicates: fixing loop for finding %d", find_id)
            removeLoop(find_id, 50)

        new_originals_qs = Finding.objects.filter(duplicate_finding__isnull=True, duplicate=True)
        if scope_qs is not None:
            new_originals_qs = new_originals_qs.filter(id__in=scope_qs.values_list("id", flat=True))
        for f in new_originals_qs:
            deduplicationLogger.info(f"New Original: {f.id}")
            f.duplicate = False
            super(Finding, f).save(skip_validation=True)

        recheck_qs = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False)
        if scope_qs is not None:
            recheck_qs = recheck_qs.filter(id__in=scope_qs.values_list("id", flat=True))
        loop_count = recheck_qs.count()
        deduplicationLogger.info(f"{loop_count} Finding found which still has Loops, please run fix loop duplicates again")
    return loop_count


def removeLoop(finding_id, counter):
    # NOTE: This function is recursive and does per-finding DB queries without prefetching.
    # It could be optimized to load the duplicate graph as ID pairs in memory and process
    # in bulk, but loops are rare (only from past bugs or high parallel load) so the
    # current implementation is acceptable.
    # get latest status
    finding = Finding.objects.get(id=finding_id)
    real_original = finding.duplicate_finding

    if not real_original or real_original is None:
        # loop fully removed
        return

    # duplicate of itself -> clear duplicate status
    if finding_id == real_original.id:
        # loop fully removed
        finding.duplicate_finding = None
        # duplicate remains True, will be set to False in fix_loop_duplicates (and logged as New Original?).
        super(Finding, finding).save(skip_validation=True)
        return

    # Only modify the findings if the original ID is lower to get the oldest finding as original
    if (real_original.id > finding_id) and (real_original.duplicate_finding is not None):
        # If not, swap them around
        tmp = finding_id
        finding_id = real_original.id
        real_original = Finding.objects.get(id=tmp)
        finding = Finding.objects.get(id=finding_id)

    if real_original in finding.original_finding.all():
        # remove the original from the duplicate list if it is there
        finding.original_finding.remove(real_original)
        super(Finding, finding).save(skip_validation=True)
    if counter <= 0:
        # Maximum recursion depth as safety method to circumvent recursion here
        return
    for f in finding.original_finding.all():
        # for all duplicates set the original as their original, get rid of self in between
        f.duplicate_finding = real_original
        super(Finding, f).save(skip_validation=True)
        super(Finding, real_original).save(skip_validation=True)
        removeLoop(f.id, counter - 1)


def add_locations(finding, form, *, replace=False):
    # TODO: Delete this after the move to Locations
    if not settings.V3_FEATURE_LOCATIONS:
        added_endpoints = save_endpoints_to_add(form.endpoints_to_add_list, finding.test.engagement.product)
        endpoint_ids = [endpoint.id for endpoint in added_endpoints]

        form_endpoints = form.cleaned_data.get("endpoints", Endpoint.objects.none())
        new_endpoints = Endpoint.objects.filter(id__in=endpoint_ids)
        if replace:
            finding.endpoints.set(form_endpoints | new_endpoints)
        else:
            finding.endpoints.set(form_endpoints | new_endpoints | finding.endpoints.all())

        for endpoint in finding.endpoints.all():
            _eps, _created = Endpoint_Status.objects.get_or_create(
                finding=finding,
                endpoint=endpoint, defaults={"date": form.cleaned_data["date"] or timezone.now()})

        return set(finding.endpoints.all())

    added_locations = save_locations_to_add(form.endpoints_to_add_list)
    location_ids = [abstract_location.location.id for abstract_location in added_locations]

    new_locations = Location.objects.filter(id__in=location_ids)
    form_locations = form.cleaned_data.get("endpoints", Location.objects.none())

    if date := form.cleaned_data.get("date"):
        audit_time = timezone.make_aware(datetime(date.year, date.month, date.day))
    else:
        audit_time = timezone.now()

    locations_to_associate = (form_locations | new_locations).distinct()

    for location in locations_to_associate:
        location.associate_with_finding(finding, audit_time=audit_time)

    return set(locations_to_associate)


def sanitize_vulnerability_ids(vulnerability_ids) -> None:
    """Remove undisired vulnerability id values"""
    vulnerability_ids = [x for x in vulnerability_ids if x.strip()]


def save_vulnerability_ids(finding, vulnerability_ids, *, delete_existing: bool = True):
    # Remove duplicates
    vulnerability_ids = list(dict.fromkeys(vulnerability_ids))

    # Remove old vulnerability ids if requested
    # Callers can set delete_existing=False when they know there are no existing IDs
    # to avoid an unnecessary delete query (e.g., for new findings)
    if delete_existing:
        Vulnerability_Id.objects.filter(finding=finding).delete()

    # Remove undisired vulnerability ids
    sanitize_vulnerability_ids(vulnerability_ids)
    # Save new vulnerability ids
    # Using bulk create throws Django 50 warnings about unsaved models...
    for vulnerability_id in vulnerability_ids:
        Vulnerability_Id(finding=finding, vulnerability_id=vulnerability_id).save()

    # Set CVE
    if vulnerability_ids:
        finding.cve = vulnerability_ids[0]
    else:
        finding.cve = None


def save_vulnerability_ids_template(finding_template, vulnerability_ids):
    """Save vulnerability IDs as newline-separated string in TextField."""
    # Remove duplicates and empty strings
    vulnerability_ids = list(dict.fromkeys([vid.strip() for vid in vulnerability_ids if vid.strip()]))

    # Save as newline-separated string
    finding_template.vulnerability_ids_text = "\n".join(vulnerability_ids) if vulnerability_ids else None

    # Set CVE for backward compatibility
    if vulnerability_ids:
        finding_template.cve = vulnerability_ids[0]
    else:
        finding_template.cve = None

    finding_template.save()


def save_endpoints_template(finding_template, endpoint_urls):
    """Save endpoint URLs as newline-separated string in TextField."""
    # Remove duplicates and empty strings
    endpoint_urls = list(dict.fromkeys([url.strip() for url in endpoint_urls if url.strip()]))
    # Save as newline-separated string
    finding_template.endpoints_text = "\n".join(endpoint_urls) if endpoint_urls else None
    finding_template.save()


def copy_template_fields_to_finding(
    finding,
    template,
    form_data=None,
    user=None,
    *,
    copy_vulnerability_ids=True,
    copy_endpoints=True,
    copy_notes=True,
):
    """
    Copy fields from Finding_Template to Finding.

    Args:
        finding: Finding instance to update
        template: Finding_Template instance (source)
        form_data: Optional dict of form cleaned_data (if provided, uses form values instead of template)
        user: User instance (required for notes)
        copy_vulnerability_ids: Whether to copy vulnerability IDs (default True)
        copy_endpoints: Whether to copy endpoints (default True)
        copy_notes: Whether to copy notes (default True)

    """
    # Helper to get value from form_data or template
    def get_value(field_name, default=None):
        if form_data and field_name in form_data:
            value = form_data.get(field_name)
            # Handle None checks for boolean/optional fields
            if value is not None or field_name not in form_data:
                return value
        return getattr(template, field_name, default)

    # Copy CVSS fields
    cvssv3 = get_value("cvssv3")
    if cvssv3:
        finding.cvssv3 = cvssv3
    cvssv3_score = get_value("cvssv3_score")
    if cvssv3_score is not None:
        finding.cvssv3_score = cvssv3_score
    cvssv4 = get_value("cvssv4")
    if cvssv4:
        finding.cvssv4 = cvssv4
    cvssv4_score = get_value("cvssv4_score")
    if cvssv4_score is not None:
        finding.cvssv4_score = cvssv4_score

    # Copy remediation planning fields
    fix_available = get_value("fix_available")
    if fix_available is not None:
        finding.fix_available = fix_available
    fix_version = get_value("fix_version")
    if fix_version:
        finding.fix_version = fix_version
    planned_remediation_version = get_value("planned_remediation_version")
    if planned_remediation_version:
        finding.planned_remediation_version = planned_remediation_version
    effort_for_fixing = get_value("effort_for_fixing")
    if effort_for_fixing:
        finding.effort_for_fixing = effort_for_fixing

    # Copy technical details fields
    steps_to_reproduce = get_value("steps_to_reproduce")
    if steps_to_reproduce:
        finding.steps_to_reproduce = steps_to_reproduce
    severity_justification = get_value("severity_justification")
    if severity_justification:
        finding.severity_justification = severity_justification
    component_name = get_value("component_name")
    if component_name:
        finding.component_name = component_name
    component_version = get_value("component_version")
    if component_version:
        finding.component_version = component_version

    # Copy vulnerability IDs
    if copy_vulnerability_ids:
        if form_data and "vulnerability_ids" in form_data:
            # Split form data (space or newline separated)
            vulnerability_ids = form_data["vulnerability_ids"]
            if isinstance(vulnerability_ids, str):
                vulnerability_ids = vulnerability_ids.split()
            save_vulnerability_ids(finding, vulnerability_ids, delete_existing=True)
        elif template.vulnerability_ids:
            save_vulnerability_ids(finding, template.vulnerability_ids, delete_existing=False)

    # Copy endpoints
    if copy_endpoints:
        endpoint_urls = None
        if form_data and form_data.get("endpoints"):
            # Parse from form data (newline-separated string)
            endpoint_urls = [url.strip() for url in form_data["endpoints"].split("\n") if url.strip()]
        elif template.endpoints:
            # Parse from template (list or newline-separated string)
            if isinstance(template.endpoints, list):
                endpoint_urls = template.endpoints
            else:
                endpoint_urls = [url.strip() for url in template.endpoints.split("\n") if url.strip()]

        if endpoint_urls:
            product = finding.test.engagement.product
            for endpoint_url in endpoint_urls:
                try:
                    if settings.V3_FEATURE_LOCATIONS:
                        saved_url = URL.create_location_from_value(endpoint_url)
                        saved_url.location.associate_with_finding(finding)
                    else:
                        # TODO: Delete this after the move to Locations
                        endpoint = Endpoint.from_uri(endpoint_url)
                        ep, _ = endpoint_get_or_create(
                            protocol=endpoint.protocol,
                            host=endpoint.host,
                            port=endpoint.port,
                            path=endpoint.path,
                            query=endpoint.query,
                            fragment=endpoint.fragment,
                            product=product,
                        )
                        Endpoint_Status.objects.get_or_create(
                            finding=finding,
                            endpoint=ep,
                            defaults={"date": finding.date or timezone.now()},
                        )
                except Exception as e:
                    logger.warning(f"Failed to parse endpoint URL '{endpoint_url}': {e}")

    # Copy notes
    if copy_notes and user:
        notes_content = None
        if form_data and form_data.get("notes"):
            notes_content = form_data["notes"]
        elif template.notes:
            notes_content = template.notes

        if notes_content:
            note = Notes(
                entry=notes_content,
                author=user,
                date=timezone.now(),
                private=False,
            )
            note.save()
            finding.notes.add(note)


def normalize_datetime(value):
    """Ensure value is timezone-aware datetime."""
    if value:
        if not isinstance(value, datetime):
            value = datetime.combine(value, datetime.min.time())
        # Make timezone-aware if naive
        if is_naive(value):
            value = make_aware(value)
    return value


def _create_note_if_provided(
    finding,
    note_entry,
    *,
    user=None,
    note_type=None,
    note_date=None,
):
    """
    Create a note for the finding when content is provided. Returns the note or None.
    Note author defaults to finding.last_reviewed_by
    """
    if not note_entry:
        return None

    new_note = Notes.objects.create(
        entry=note_entry,
        author=user or finding.last_reviewed_by,
        note_type=note_type,
        date=note_date,
    )
    finding.notes.add(new_note)
    return new_note


def _save_finding_with_jira_sync(finding, *, new_note=None):
    """Persist finding and apply JIRA sync behavior used by finding status actions."""
    push_to_jira = False
    finding_in_group = finding.has_finding_group
    jira_issue_exists = finding.has_jira_issue or (
        finding.finding_group and finding.finding_group.has_jira_issue
    )
    jira_instance = jira_helper.get_jira_instance(finding)
    jira_project = jira_helper.get_jira_project(finding)

    if jira_issue_exists:
        push_to_jira = (
            jira_helper.is_push_all_issues(finding)
            or (jira_instance and jira_instance.finding_jira_sync)
        )
        if new_note and (getattr(jira_project, "push_notes", False) or push_to_jira) and not finding_in_group:
            jira_helper.add_comment(finding, new_note, force_push=True)

    finding.save(push_to_jira=(push_to_jira and not finding_in_group))
    if push_to_jira and finding_in_group:
        jira_helper.push_to_jira(finding.finding_group)


def close_finding(
    *,
    finding,
    user,
    is_mitigated,
    mitigated,
    mitigated_by,
    false_p,
    out_of_scope,
    duplicate,
    note_entry=None,
    note_type=None,
) -> None:
    """
    Shared close logic used by UI and API.

    Handles status updates, endpoint statuses, risk acceptance, external issues,
    JIRA sync, and notification.
    """
    # Core status updates
    finding.is_mitigated = is_mitigated
    current_time = now()
    mitigated_date = normalize_datetime(mitigated) or current_time
    finding.mitigated = mitigated_date
    finding.mitigated_by = mitigated_by or user
    finding.active = False
    finding.false_p = bool(false_p)
    finding.out_of_scope = bool(out_of_scope)
    finding.duplicate = bool(duplicate)
    finding.under_review = False
    finding.last_reviewed = mitigated_date
    finding.last_reviewed_by = user

    # Create note if provided
    new_note = _create_note_if_provided(
        finding,
        note_entry,
        note_type=note_type,
        note_date=mitigated_date,
    )

    if settings.V3_FEATURE_LOCATIONS:
        # Related locations
        for ref in finding.locations.all():
            ref.set_status(FindingLocationStatus.Mitigated, finding.mitigated_by, mitigated_date)
    else:
        # TODO: Delete this after the move to Locations
        # Endpoint statuses
        for status in finding.status_finding.all():
            status.mitigated_by = finding.mitigated_by
            status.mitigated_time = mitigated_date
            status.mitigated = True
            status.last_modified = current_time
            status.save()

    # Risk acceptance
    ra_helper.risk_unaccept(user, finding, perform_save=False)

    # External issues (best effort)
    close_external_issue(finding.id, "Closed by defectdojo", "github")

    _save_finding_with_jira_sync(finding, new_note=new_note)

    # Notification
    create_notification(
        event="finding_closed",
        title=f"Closing of {finding.title}",
        finding=finding,
        description=f'The finding "{finding.title}" was closed by {user}',
        url=reverse("view_finding", args=(finding.id,)),
    )


def verify_finding(
    *,
    finding,
    user,
    note_entry=None,
    note_type=None,
) -> None:
    """Shared verify logic used by UI and API."""
    verification_time = now()

    finding.verified = True
    finding.last_reviewed = verification_time
    finding.last_reviewed_by = user
    finding.last_status_update = verification_time

    new_note = _create_note_if_provided(
        finding,
        note_entry,
        note_type=note_type,
        note_date=verification_time,
    )

    _save_finding_with_jira_sync(finding, new_note=new_note)
