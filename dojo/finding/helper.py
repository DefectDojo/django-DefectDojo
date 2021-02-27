import logging
from datetime import datetime
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


def is_newly_mitigated(changed_fields) -> bool:
    # logger.debug('changed_fields: %s', changed_fields)
    if not changed_fields:
        return False

    if 'active' in changed_fields:
        return changed_fields['active'] == (False, True)

    if 'is_Mitigated' in changed_fields:
        return changed_fields['is_Mitigated'] == (True, False)

    return False


def is_mitigated_meta_fields_modified(changed_fields) -> bool:
    # logger.debug('changed_fields: %s', changed_fields)
    if not changed_fields:
        return False

    if 'mitigated' in changed_fields:
        return changed_fields['mitigated'][0] is not None and changed_fields['mitigated'][1] is not None

    if 'mitigated_by' in changed_fields:
        return changed_fields['mitigated_by'][0] is not None and changed_fields['mitigated_by'][1] is not None


def update_finding_status(new_state_finding, user, changed_fields=None):
    if is_newly_mitigated(changed_fields):
        # when mitigating a finding, the meta fields can only be editted if allowed
        if can_edit_mitigated_data(user):
            # only set if it was not already set by user
            new_state_finding.mitigated = new_state_finding.mitigated or timezone.now()
            new_state_finding.mitigated_by = new_state_finding.mitigated_by or user
        else:
            new_state_finding.mitigated = timezone.now()
            new_state_finding.mitigated_by = user
        new_state_finding.is_Mitigated = True

    elif is_mitigated_meta_fields_modified(changed_fields):
        # if edit not allowed, restore old values
        if not can_edit_mitigated_data(user):
            # this shouldn't occur due to access checks earlier in the request
            raise PermissionError('user %s is not allowed to change mitigated and mitigated_by fields', user)

    if 'false_p' in changed_fields or 'out_of_scope' in changed_fields:
        if new_state_finding.false_p or new_state_finding.out_of_scope:
            new_state_finding.mitigated = new_state_finding.mitigated or timezone.now()
            new_state_finding.mitigated_by = new_state_finding.mitigated_by or user
            new_state_finding.is_Mitigated = True
            new_state_finding.active = False
            new_state_finding.verified = False

    # always reset some fields if the finding is active
    if new_state_finding.active is True:
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

    # ensure mitigate data is set or cleared based on is_Mitigated boolean
    if new_state_finding.is_Mitigated and new_state_finding.mitigated is None:
        new_state_finding.mitigated = datetime.now()
        if settings.USE_TZ and new_state_finding.mitigated and new_state_finding.mitigated.tzinfo is None:
            new_state_finding.mitigated = timezone.make_aware(new_state_finding.mitigated,
                                                              timezone.get_default_timezone())

    if new_state_finding.is_Mitigated and new_state_finding.mitigated_by is None:
        finding_status_changed = True
        new_state_finding.mitigated_by = user

    if not new_state_finding.is_Mitigated and new_state_finding.mitigated is not None:
        finding_status_changed = True
        new_state_finding.mitigated = None

    if not new_state_finding.is_Mitigated and new_state_finding.mitigated_by is not None:
        finding_status_changed = True
        new_state_finding.mitigated_by = None


def can_edit_mitigated_data(user):
    return settings.EDITABLE_MITIGATED_DATA and user.is_superuser
