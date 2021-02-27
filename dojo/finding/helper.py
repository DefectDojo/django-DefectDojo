import logging
from django.utils import timezone
from django.conf import settings
from fieldsignals import pre_save_changed
from dojo.models import Finding
from dojo.utils import get_current_user

logger = logging.getLogger(__name__)


# this signal is triggered just before a finding is getting saved
# and one of the status related fields has changed
# this allows us to:
# - set any depending fields such as mitigated_by, mitigated, etc.
# - update any audit log / status history
def pre_save_finding_status_change(sender, instance, changed_fields=None, **kwargs):
    # some code is cloning findings by setting id/pk to None, ignore those, will be handled on next save
    if not instance.id:
        logger.info('ignoring save of finding without id')
        return

    logger.info('%i: changed status fields pre_save: %s', instance.id or 0, changed_fields)

    for field, (old, new) in changed_fields.items():
        logger.debug("%i: %s changed from %s to %s" % (instance.id or 0, field, old, new))
        update_finding_status(instance, get_current_user(), changed_fields)


# also get signal when id is set/changed so we can process new findings
pre_save_changed.connect(pre_save_finding_status_change, sender=Finding, fields=['id', 'active', 'verfied', 'false_p', 'is_Mitigated', 'mitigated', 'mitigated_by', 'out_of_scope', 'risk_accepted'])
# pre_save_changed.connect(pre_save_finding_status_change, sender=Finding)
# post_save_changed.connect(pre_save_finding_status_change, sender=Finding, fields=['active', 'verfied', 'false_p', 'is_Mitigated', 'mitigated', 'mitigated_by', 'out_of_scope'])


def is_newly_mitigated(finding, changed_fields) -> bool:
    # logger.debug('changed_fields: %s', changed_fields)
    if not changed_fields:
        return False

    if 'active' in changed_fields:
        return changed_fields['active'] == (True, False)

    if 'is_Mitigated' in changed_fields:
        return changed_fields['is_Mitigated'] == (False, True)

    # new findings arrive here with only the id field changed
    if 'id' in changed_fields and len(changed_fields) == 1 and finding.is_Mitigated:
        return True

    return False


def update_finding_status(new_state_finding, user, changed_fields=None):
    now = timezone.now()

    if is_newly_mitigated(new_state_finding, changed_fields):
        # when mitigating a finding, the meta fields can only be editted if allowed
        logger.debug('finding being mitigated, set mitigated and mitigated_by fields')

        if can_edit_mitigated_data(user):
            # only set if it was not already set by user
            # not sure if this check really covers all cases, but if we make it more strict
            # it will cause all kinds of issues I believe with new findings etc
            new_state_finding.mitigated = new_state_finding.mitigated or now
            new_state_finding.mitigated_by = new_state_finding.mitigated_by or user
        else:
            new_state_finding.mitigated = now
            new_state_finding.mitigated_by = user

        if not new_state_finding.duplicate:
            # duplicate doesn't mean mitigated (but false_p and out_of_scope does....)
            new_state_finding.is_Mitigated = True

    if 'false_p' in changed_fields or 'out_of_scope' in changed_fields:
        if new_state_finding.false_p or new_state_finding.out_of_scope:
            new_state_finding.mitigated = new_state_finding.mitigated or now
            new_state_finding.mitigated_by = new_state_finding.mitigated_by or user
            new_state_finding.is_Mitigated = True
            new_state_finding.active = False
            new_state_finding.verified = False

    # always reset some fields if the finding is active
    if new_state_finding.active:
        logger.debug('finding is active, so setting all other fields to False/None')
        new_state_finding.false_p = False
        new_state_finding.out_of_scope = False
        new_state_finding.mitigated = None
        new_state_finding.mitigated_by = None
        new_state_finding.is_Mitigated = False

    # always reset some fields if the finding is not a duplicate
    if not new_state_finding.duplicate:
        new_state_finding.duplicate = False
        new_state_finding.duplicate_finding = None

    # make sure these fields are set
    if new_state_finding.is_Mitigated:
        new_state_finding.mitigated = new_state_finding.mitigated or now
        new_state_finding.mitigated_by = new_state_finding.mitigated_by or user

    if not new_state_finding.is_Mitigated:
        new_state_finding.mitigated = None
        new_state_finding.mitigated_by = None


def can_edit_mitigated_data(user):
    return settings.EDITABLE_MITIGATED_DATA and user.is_superuser
