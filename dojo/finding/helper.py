import logging
from contextlib import suppress
from datetime import datetime
from time import strftime

from django.conf import settings
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
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
from dojo.endpoint.utils import save_endpoints_to_add
from dojo.file_uploads.helper import delete_related_files
from dojo.finding.deduplication import (
    dedupe_batch_of_findings,
    do_dedupe_finding,
    get_finding_models_for_deduplication,
)
from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Finding_Group,
    Notes,
    System_Settings,
    Test,
    Vulnerability_Id,
    Vulnerability_Id_Template,
)
from dojo.notes.helper import delete_related_notes
from dojo.notifications.helper import create_notification
from dojo.tools import tool_issue_updater
from dojo.utils import (
    calculate_grade,
    close_external_issue,
    do_false_positive_history,
    get_current_user,
    mass_model_updater,
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

    if is_new_finding or "verified" in changed_fields:
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
        finding_group.name = finding_group_name
    elif finding_group.components:
        finding_group.name = finding_group.components
    try:
        finding_group.save()
    except IntegrityError as ie:
        if "already exists" in str(ie):
            finding_group.name = finding_group_name + finding_group_name_dummy
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
        if not creator:
            creator = kwargs.get("async_user")
        test = findings[0].test

        if create_finding_groups_for_all_findings or len(findings) > 1:
            # Only create a finding group if we have more than one finding for a given finding group, unless configured otherwise
            finding_group, created = Finding_Group.objects.get_or_create(test=test, creator=creator, name=name)
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
                        finding_group, created = Finding_Group.objects.get_or_create(test=test, creator=creator, name=name)
                        finding_group.findings.add(f)
                if created:
                    finding_group.findings.add(*findings)


@dojo_model_to_id
@dojo_async_task(signature=True)
@app.task
@dojo_model_from_id
def post_process_finding_save_signature(finding, dedupe_option=True, rules_option=True, product_grading_option=True,  # noqa: FBT002
             issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):  # noqa: FBT002 - this is bit hard to fix nice have this universally fixed
    """
    Returns a task signature for post-processing a finding. This is useful for creating task signatures
    that can be used in chords or groups or to await results. We need this extra method because of our dojo_async decorator.
    If we use more of these celery features, we should probably move away from that decorator.
    """
    return post_process_finding_save_internal(finding, dedupe_option, rules_option, product_grading_option,
                                   issue_updater_option, push_to_jira, user, *args, **kwargs)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def post_process_finding_save(finding, dedupe_option=True, rules_option=True, product_grading_option=True,  # noqa: FBT002
             issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):  # noqa: FBT002 - this is bit hard to fix nice have this universally fixed

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
                do_dedupe_finding(finding, *args, **kwargs)
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
            calculate_grade(finding.test.engagement.product)
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


@dojo_async_task(signature=True)
@app.task
def post_process_findings_batch_signature(finding_ids, *args, dedupe_option=True, rules_option=True, product_grading_option=True,
             issue_updater_option=True, push_to_jira=False, user=None, **kwargs):
    return post_process_findings_batch(finding_ids, *args, dedupe_option=dedupe_option, rules_option=rules_option, product_grading_option=product_grading_option, issue_updater_option=issue_updater_option, push_to_jira=push_to_jira, user=user, **kwargs)
    # Pass arguments as keyword arguments to ensure Celery properly serializes them


@dojo_async_task
@app.task
def post_process_findings_batch(finding_ids, *args, dedupe_option=True, rules_option=True, product_grading_option=True,
             issue_updater_option=True, push_to_jira=False, user=None, **kwargs):

    logger.debug(
        f"post_process_findings_batch called: finding_ids_count={len(finding_ids) if finding_ids else 0}, "
        f"args={args}, dedupe_option={dedupe_option}, rules_option={rules_option}, "
        f"product_grading_option={product_grading_option}, issue_updater_option={issue_updater_option}, "
        f"push_to_jira={push_to_jira}, user={user.id if user else None}, kwargs={kwargs}",
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
            for finding in findings:
                do_false_positive_history(finding, *args, **kwargs)

    # Non-status changing tasks
    if issue_updater_option:
        for finding in findings:
            tool_issue_updater.async_tool_issue_update(finding)

    if product_grading_option and system_settings.enable_product_grade:
        calculate_grade(findings[0].test.engagement.product)

    if push_to_jira:
        for finding in findings:
            if finding.has_jira_issue or not finding.finding_group:
                jira_helper.push_to_jira(finding)
            else:
                jira_helper.push_to_jira(finding.finding_group)
    else:
        logger.debug("push_to_jira is False, not ushing to JIRA")


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


def reset_duplicate_before_delete(dupe):
    dupe.duplicate_finding = None
    dupe.duplicate = False


def reset_duplicates_before_delete(qs):
    mass_model_updater(Finding, qs, reset_duplicate_before_delete, fields=["duplicate", "duplicate_finding"])


def set_new_original(finding, new_original):
    if finding.duplicate:
        finding.duplicate_finding = new_original


# can't use model to id here due to the queryset
# @dojo_async_task
# @app.task
def reconfigure_duplicate_cluster(original, cluster_outside):
    # when a finding is deleted, and is an original of a duplicate cluster, we have to chose a new original for the cluster
    # only look for a new original if there is one outside this test
    if original is None or cluster_outside is None or len(cluster_outside) == 0:
        return

    if settings.DUPLICATE_CLUSTER_CASCADE_DELETE:
        cluster_outside.order_by("-id").delete()
    else:
        logger.debug("reconfigure_duplicate_cluster: cluster_outside: %s", cluster_outside)
        # set new original to first finding in cluster (ordered by id)
        new_original = cluster_outside.order_by("id").first()
        if new_original:
            logger.debug("changing original of duplicate cluster %d to: %s:%s", original.id, new_original.id, new_original.title)

            new_original.duplicate = False
            new_original.duplicate_finding = None
            new_original.active = original.active
            new_original.is_mitigated = original.is_mitigated
            new_original.save_no_options()
            new_original.found_by.set(original.found_by.all())

        # if the cluster is size 1, there's only the new original left
        if new_original and len(cluster_outside) > 1:
            # for find in cluster_outside:
            #     if find != new_original:
            #         find.duplicate_finding = new_original
            #         find.save_no_options()

            mass_model_updater(Finding, cluster_outside, lambda f: set_new_original(f, new_original), fields=["duplicate_finding"])


def prepare_duplicates_for_delete(test=None, engagement=None):
    logger.debug("prepare duplicates for delete, test: %s, engagement: %s", test.id if test else None, engagement.id if engagement else None)
    if test is None and engagement is None:
        logger.warning("nothing to prepare as test and engagement are None")

    fix_loop_duplicates()

    # get all originals in the test/engagement
    originals = Finding.objects.filter(original_finding__isnull=False)
    if engagement:
        originals = originals.filter(test__engagement=engagement)
    if test:
        originals = originals.filter(test=test)

    # use distinct to flatten the join result
    originals = originals.distinct()

    if len(originals) == 0:
        logger.debug("no originals found, so no duplicates to prepare for deletion of original")
        return

    # remove the link to the original from the duplicates inside the cluster so they can be safely deleted by the django framework
    total = len(originals)
    # logger.debug('originals: %s', [original.id for original in originals])
    for i, original in enumerate(originals):
        logger.debug("%d/%d: preparing duplicate cluster for deletion of original: %d", i + 1, total, original.id)
        cluster_inside = original.original_finding.all()
        if engagement:
            cluster_inside = cluster_inside.filter(test__engagement=engagement)

        if test:
            cluster_inside = cluster_inside.filter(test=test)

        if len(cluster_inside) > 0:
            reset_duplicates_before_delete(cluster_inside)

        # reconfigure duplicates outside test/engagement
        cluster_outside = original.original_finding.all()
        if engagement:
            cluster_outside = cluster_outside.exclude(test__engagement=engagement)

        if test:
            cluster_outside = cluster_outside.exclude(test=test)

        if len(cluster_outside) > 0:
            reconfigure_duplicate_cluster(original, cluster_outside)

        logger.debug("done preparing duplicate cluster for deletion of original: %d", original.id)


@receiver(pre_delete, sender=Test)
def test_pre_delete(sender, instance, **kwargs):
    logger.debug("test pre_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))
    prepare_duplicates_for_delete(test=instance)


@receiver(post_delete, sender=Test)
def test_post_delete(sender, instance, **kwargs):
    logger.debug("test post_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))


@receiver(pre_delete, sender=Engagement)
def engagement_pre_delete(sender, instance, **kwargs):
    logger.debug("engagement pre_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))
    prepare_duplicates_for_delete(engagement=instance)


@receiver(post_delete, sender=Engagement)
def engagement_post_delete(sender, instance, **kwargs):
    logger.debug("engagement post_delete, sender: %s instance: %s", to_str_typed(sender), to_str_typed(instance))


def fix_loop_duplicates():
    """Due to bugs in the past and even currently when under high parallel load, there can be transitive duplicates."""
    """ i.e. A -> B -> C. This can lead to problems when deleting findingns, performing deduplication, etc """
    # Build base queryset without selecting full rows to minimize memory
    loop_qs = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False)

    # Use COUNT(*) at the DB instead of materializing the queryset
    loop_count = loop_qs.count()

    if loop_count > 0:
        deduplicationLogger.info(f"Identified {loop_count} Findings with Loops")
        # Stream IDs only in descending order to avoid loading full Finding rows
        for find_id in loop_qs.order_by("-id").values_list("id", flat=True).iterator(chunk_size=1000):
            removeLoop(find_id, 50)

        new_originals = Finding.objects.filter(duplicate_finding__isnull=True, duplicate=True)
        for f in new_originals:
            deduplicationLogger.info(f"New Original: {f.id}")
            f.duplicate = False
            super(Finding, f).save()

        loop_count = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False).count()
        deduplicationLogger.info(f"{loop_count} Finding found which still has Loops, please run fix loop duplicates again")
    return loop_count


def removeLoop(finding_id, counter):
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
        super(Finding, finding).save()
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
        super(Finding, finding).save()
    if counter <= 0:
        # Maximum recursion depth as safety method to circumvent recursion here
        return
    for f in finding.original_finding.all():
        # for all duplicates set the original as their original, get rid of self in between
        f.duplicate_finding = real_original
        super(Finding, f).save()
        super(Finding, real_original).save()
        removeLoop(f.id, counter - 1)


def add_endpoints(new_finding, form):
    added_endpoints = save_endpoints_to_add(form.endpoints_to_add_list, new_finding.test.engagement.product)
    endpoint_ids = [endpoint.id for endpoint in added_endpoints]

    new_finding.endpoints.set(form.cleaned_data["endpoints"] | Endpoint.objects.filter(id__in=endpoint_ids))

    for endpoint in new_finding.endpoints.all():
        _eps, _created = Endpoint_Status.objects.get_or_create(
            finding=new_finding,
            endpoint=endpoint, defaults={"date": form.cleaned_data["date"] or timezone.now()})


def save_vulnerability_ids(finding, vulnerability_ids):
    # Remove duplicates
    vulnerability_ids = list(dict.fromkeys(vulnerability_ids))

    # Remove old vulnerability ids
    Vulnerability_Id.objects.filter(finding=finding).delete()

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
    # Remove duplicates
    vulnerability_ids = list(dict.fromkeys(vulnerability_ids))

    # Remove old vulnerability ids
    Vulnerability_Id_Template.objects.filter(finding_template=finding_template).delete()

    # Save new vulnerability ids
    for vulnerability_id in vulnerability_ids:
        Vulnerability_Id_Template(finding_template=finding_template, vulnerability_id=vulnerability_id).save()

    # Set CVE
    if vulnerability_ids:
        finding_template.cve = vulnerability_ids[0]
    else:
        finding_template.cve = None


def normalize_datetime(value):
    """Ensure value is timezone-aware datetime."""
    if value:
        if not isinstance(value, datetime):
            value = datetime.combine(value, datetime.min.time())
        # Make timezone-aware if naive
        if is_naive(value):
            value = make_aware(value)
    return value


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
    new_note = None
    if note_entry:
        new_note = Notes.objects.create(
            entry=note_entry,
            author=user,
            note_type=note_type,
            date=mitigated_date,
        )
        finding.notes.add(new_note)

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
    close_external_issue(finding, "Closed by defectdojo", "github")

    # JIRA sync
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

    # Persist and push JIRA if applicable
    finding.save(push_to_jira=(push_to_jira and not finding_in_group))
    if push_to_jira and finding_in_group:
        jira_helper.push_to_jira(finding.finding_group)

    # Notification
    create_notification(
        event="finding_closed",
        title=f"Closing of {finding.title}",
        finding=finding,
        description=f'The finding "{finding.title}" was closed by {user}',
        url=reverse("view_finding", args=(finding.id,)),
    )
