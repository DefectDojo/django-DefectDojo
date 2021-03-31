from dojo.celery import app
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
import logging
from time import strftime
from django.utils import timezone
from django.conf import settings
from fieldsignals import pre_save_changed
from dojo.models import Finding, Finding_Group
from dojo.utils import get_current_user
from dojo.models import Finding, System_Settings

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


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

    logger.debug('%i: changed status fields pre_save: %s', instance.id or 0, changed_fields)

    for field, (old, new) in changed_fields.items():
        logger.debug("%i: %s changed from %s to %s" % (instance.id or 0, field, old, new))
        user = None
        if get_current_user() and get_current_user().is_authenticated:
            user = get_current_user()
        update_finding_status(instance, user, changed_fields)


# also get signal when id is set/changed so we can process new findings
pre_save_changed.connect(pre_save_finding_status_change, sender=Finding, fields=['id', 'active', 'verfied', 'false_p', 'is_Mitigated', 'mitigated', 'mitigated_by', 'out_of_scope', 'risk_accepted'])
# pre_save_changed.connect(pre_save_finding_status_change, sender=Finding)
# post_save_changed.connect(pre_save_finding_status_change, sender=Finding, fields=['active', 'verfied', 'false_p', 'is_Mitigated', 'mitigated', 'mitigated_by', 'out_of_scope'])


def update_finding_status(new_state_finding, user, changed_fields=None):
    now = timezone.now()

    is_new_finding = changed_fields and len(changed_fields) == 1 and 'id' in changed_fields

    # activated
    # reactivated
    # closed / mitigated
    # false positivized
    # out_of_scopified
    # marked as duplicate
    # marked as original

    if 'is_Mitigated' in changed_fields or is_new_finding:
        # finding is being mitigated
        if new_state_finding.is_Mitigated:
            # when mitigating a finding, the meta fields can only be editted if allowed
            logger.debug('finding being mitigated, set mitigated and mitigated_by fields')

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

    # people may try to remove mitigated/mitigated_by by accident
    if new_state_finding.is_Mitigated:
        new_state_finding.mitigated = new_state_finding.mitigated or now
        new_state_finding.mitigated_by = new_state_finding.mitigated_by or user

    if 'active' in changed_fields or is_new_finding:
        # finding is being (re)activated
        if new_state_finding.active:
            new_state_finding.false_p = False
            new_state_finding.out_of_scope = False
            new_state_finding.is_Mitigated = False
            new_state_finding.mitigated = None
            new_state_finding.mitigated_by = None
        else:
            # finding is being deactivated
            pass

    if 'verified' in changed_fields or is_new_finding:
        pass

    if 'false_p' in changed_fields or 'out_of_scope' in changed_fields or is_new_finding:
        # existing behaviour is that false_p or out_of_scope implies mitigated
        if new_state_finding.false_p or new_state_finding.out_of_scope:
            new_state_finding.mitigated = new_state_finding.mitigated or now
            new_state_finding.mitigated_by = new_state_finding.mitigated_by or user
            new_state_finding.is_Mitigated = True
            new_state_finding.active = False
            new_state_finding.verified = False

    # always reset some fields if the finding is not a duplicate
    if not new_state_finding.duplicate:
        new_state_finding.duplicate = False
        new_state_finding.duplicate_finding = None

    new_state_finding.last_status_update = now


def can_edit_mitigated_data(user):
    return settings.EDITABLE_MITIGATED_DATA and user.is_superuser



@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def post_process_finding_save(finding, dedupe_option=True, false_history=False, rules_option=True, product_grading_option=True,
             issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):

    system_settings = System_Settings.objects.get()

    # STEP 1 run all status changing tasks sequentially to avoid race conditions
    if dedupe_option:
        if finding.hash_code is not None:
            if system_settings.enable_deduplication:
                from dojo.utils import do_dedupe_finding
                do_dedupe_finding(finding, *args, **kwargs)
            else:
                deduplicationLogger.debug("skipping dedupe because it's disabled in system settings")
        else:
            deduplicationLogger.warning("skipping dedupe because hash_code is None")

    if false_history:
        if system_settings.false_positive_history:
            from dojo.utils import do_false_positive_history
            do_false_positive_history(finding, *args, **kwargs)
        else:
            deduplicationLogger.debug("skipping false positive history because it's disabled in system settings")

    # STEP 2 run all non-status changing tasks as celery tasks in the background
    if issue_updater_option:
        from dojo.tools import tool_issue_updater
        tool_issue_updater.async_tool_issue_update(finding)

    if product_grading_option:
        if system_settings.enable_product_grade:
            from dojo.utils import calculate_grade
            calculate_grade(finding.test.engagement.product)
        else:
            deduplicationLogger.debug("skipping product grading because it's disabled in system settings")

    # Adding a snippet here for push to JIRA so that it's in one place
    if push_to_jira:
        logger.debug('pushing finding %s to jira from finding.save()', finding.pk)
        import dojo.jira_link.helper as jira_helper
        jira_helper.push_to_jira(finding)

        
def create_finding_group(finds, finding_group_name):
    logger.debug('creating finding_group_create')
    if not finds or len(finds) == 0:
        raise ValueError('cannot create empty Finding Group')

    finding_group_name_dummy = 'bulk group ' + strftime("%a, %d %b  %Y %X", timezone.now().timetuple())

    finding_group = Finding_Group(test=finds[0].test)
    finding_group.creator = get_current_user()
    finding_group.name = finding_group_name + finding_group_name_dummy
    finding_group.save()
    available_findings = [find for find in finds if not find.finding_group_set.all()]
    finding_group.findings.set(available_findings)

    # if user provided a name, we use that, else:
    # if we have components, we may set a nice name but catch 'name already exist' exceptions
    try:
        if finding_group_name:
            finding_group.name = finding_group_name
        elif finding_group.components:
            finding_group.name = finding_group.components
        finding_group.save()
    except:
        pass

    added = len(available_findings)
    skipped = len(finds) - added
    return finding_group, added, skipped


def add_to_finding_group(finding_group, finds):
    added = 0
    skipped = 0
    available_findings = [find for find in finds if not find.finding_group_set.all()]
    finding_group.findings.add(*available_findings)

    added = len(available_findings)
    skipped = len(finds) - added
    return finding_group, added, skipped


def remove_from_finding_group(finds):
    removed = 0
    skipped = 0
    affected_groups = []
    for find in finds:
        groups = find.finding_group_set.all()
        if not groups:
            skipped += 1
            continue

        for group in find.finding_group_set.all():
            group.findings.remove(find)
            affected_groups.append(group)

        removed += 1

    return affected_groups, removed, skipped

# def delete_finding_group(finding_group):
#     pass

