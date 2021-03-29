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
        logger.debug('ignoring save of finding without id')
        return

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
