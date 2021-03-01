import logging
from datetime import datetime
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)


def update_finding_status(new_state_finding, request_user, old_state_finding=None) -> bool:
    finding_status_changed = False

    if old_state_finding is not None:
        if old_state_finding.active is True and new_state_finding.active is False:
            if can_edit_mitigated_data(request_user):
                # only set if it was not already set by user
                new_state_finding.mitigated = new_state_finding.mitigated or timezone.now()
                new_state_finding.mitigated_by = new_state_finding.mitigated_by or request_user
            else:
                new_state_finding.mitigated = timezone.now()
                new_state_finding.mitigated_by = request_user
            new_state_finding.is_Mitigated = True
    if new_state_finding.false_p or new_state_finding.out_of_scope:
        new_state_finding.mitigated = timezone.now()
        new_state_finding.mitigated_by = request_user
        new_state_finding.is_Mitigated = True
        new_state_finding.active = False
        new_state_finding.verified = False
    if new_state_finding.active is True:
        new_state_finding.false_p = False
        new_state_finding.out_of_scope = False
        new_state_finding.mitigated = None
        new_state_finding.mitigated_by = None
        new_state_finding.is_Mitigated = False
    if not new_state_finding.duplicate:
        new_state_finding.duplicate = False
        new_state_finding.duplicate_finding = None

    # ensure mitigate data is set or cleared based on is_Mitigated boolean
    if new_state_finding.is_Mitigated and new_state_finding.mitigated is None:
        finding_status_changed = True
        new_state_finding.mitigated = datetime.now()
        if settings.USE_TZ:
            new_state_finding.mitigated = timezone.make_aware(new_state_finding.mitigated,
                                                              timezone.get_default_timezone())
    if new_state_finding.is_Mitigated and new_state_finding.mitigated_by is None:
        finding_status_changed = True
        new_state_finding.mitigated_by = request_user
    if not new_state_finding.is_Mitigated and new_state_finding.mitigated is not None:
        finding_status_changed = True
        new_state_finding.mitigated = None
    if not new_state_finding.is_Mitigated and new_state_finding.mitigated_by is not None:
        finding_status_changed = True
        new_state_finding.mitigated_by = None

    return finding_status_changed


def can_edit_mitigated_data(request_user):
    return settings.EDITABLE_MITIGATED_DATA and request_user.is_superuser
