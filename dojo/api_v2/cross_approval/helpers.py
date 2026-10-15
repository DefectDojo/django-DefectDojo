from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from dojo.celery import app
from dojo.engine_tools.helpers import Constants, get_note, get_reviewers_members, get_unique_ids_filter
from dojo.models import Finding
from dojo.notifications.helper import create_notification
from dojo.user.queries import get_user

from .models import CrossApprovalExclusion, CrossApprovalRequest, CrossApprovalRequestLog


CROSS_APPROVAL_CSV_SEPARATOR = ","
CROSS_APPROVAL_DEFAULT_WHERE = "all"


def _request_owner(cross_approval_request):
    return cross_approval_request.owner


def _component_values(exclusion):
    return exclusion.component_values or []


def _where_values(exclusion):
    where_value = (exclusion.where or "").strip()
    if not where_value or where_value.casefold() == CROSS_APPROVAL_DEFAULT_WHERE:
        return []

    return _csv_values(where_value)


def _csv_values(value):
    normalized_values = []
    if not isinstance(value, str):
        return normalized_values

    for raw_item in value.split(CROSS_APPROVAL_CSV_SEPARATOR):
        normalized_item = raw_item.strip().casefold()
        if normalized_item and normalized_item not in normalized_values:
            normalized_values.append(normalized_item)
    return normalized_values


def _filter_findings_by_component(findings, exclusion):
    component_values = _component_values(exclusion)

    if not component_values:
        return findings

    component_filter = Q()
    for component_value in component_values:
        component_filter |= Q(description__icontains=component_value)
    return findings.filter(component_filter)


def _filter_findings_by_where(findings, exclusion):
    where_values = _where_values(exclusion)

    if not where_values:
        return findings

    where_filter = Q()
    for where_value in where_values:
        where_filter |= Q(tags__name__iexact=where_value)
    return findings.filter(where_filter).distinct()


def _get_findings(exclusion, active_only=True):
    finding_filters = [get_unique_ids_filter(exclusion.vulnerability_id)]
    if active_only:
        finding_filters.append(Q(active=True))
    findings = Finding.objects.filter(*finding_filters).prefetch_related("tags", "notes")
    findings = _filter_findings_by_component(findings, exclusion)
    findings = _filter_findings_by_where(findings, exclusion)

    priority_values = _csv_values(exclusion.priority)
    severity_values = _csv_values(exclusion.severity)
    if priority_values or severity_values:
        findings = [
            finding for finding in findings
            if (
                priority_values
                and (finding.priority_classification or "").casefold() in priority_values
            ) or (
                severity_values
                and (finding.severity or "").casefold() in severity_values
            )
        ]
    return findings


@app.task
def apply_cross_approval_exclusion(exclusion_id):
    exclusion = CrossApprovalExclusion.objects.select_related("request").get(pk=exclusion_id)
    if (
        exclusion.request.status != "approved"
        or exclusion.expired_at
        or exclusion.expired_date < timezone.localdate()
    ):
        return

    system_user = get_user(settings.SYSTEM_USER)
    request_url = reverse("crossapproval_list")
    note = get_note(
        system_user,
        f"Finding added by cross-approval request {exclusion.request_id}: {request_url}",
    )
    request_owner = _request_owner(exclusion.request)
    for finding in _get_findings(exclusion):
        finding.tags.add("white_list", request_owner)
        finding.active = False
        finding.risk_status = Constants.ON_WHITELIST.value
        finding.notes.add(note)
        finding.save(update_fields=["active", "risk_status"])


def revert_cross_approval_exclusion(exclusion, exclude_request_id=None):
    system_user = get_user(settings.SYSTEM_USER)
    note = get_note(
        system_user,
        f"Finding removed from cross-approval request {exclusion.request_id}.",
    )
    request_owner = _request_owner(exclusion.request)
    findings = Finding.objects.filter(
        get_unique_ids_filter(exclusion.vulnerability_id),
        risk_status=Constants.ON_WHITELIST.value,
        tags__name=request_owner,
    ).prefetch_related("tags")
    other_exclusions = CrossApprovalExclusion.objects.filter(
        vulnerability_id=exclusion.vulnerability_id,
        request__owner=request_owner,
        request__status="approved",
        expired_at__isnull=True,
        expired_date__gte=timezone.localdate(),
    )
    if exclude_request_id:
        other_exclusions = other_exclusions.exclude(request_id=exclude_request_id)
    else:
        other_exclusions = other_exclusions.exclude(pk=exclusion.pk)
    findings_covered_by_other_exclusions = {
        finding.pk
        for other_exclusion in other_exclusions
        for finding in _get_findings(other_exclusion, active_only=False)
    }
    for finding in findings:
        if finding.pk in findings_covered_by_other_exclusions:
            continue
        finding.tags.remove(request_owner)
        if "white_list" in finding.tags:
            finding.tags.remove("white_list")
        if not finding.is_mitigated:
            finding.active = True
        finding.risk_status = "Risk Active"
        finding.notes.add(note)
        finding.save(update_fields=["active", "risk_status"])


def expire_cross_approval_exclusion(exclusion, user):
    if exclusion.expired_at:
        return
    exclusion.expired_at = timezone.now()
    exclusion.save(update_fields=["expired_at"])
    revert_cross_approval_exclusion(exclusion)
    log_status_change(exclusion.request, user, "approved", "expired")


def reopen_cross_approval_exclusion(exclusion, user):
    if not exclusion.expired_at or exclusion.expired_date < timezone.localdate():
        return False
    exclusion.expired_at = None
    exclusion.save(update_fields=["expired_at"])
    log_status_change(exclusion.request, user, "expired", "approved")
    transaction.on_commit(
        lambda exclusion_id=exclusion.pk: apply_cross_approval_exclusion.delay(exclusion_id)
    )
    return True


@app.task
def revert_cross_approval_exclusion_task(exclusion_id):
    exclusion = CrossApprovalExclusion.objects.select_related("request").get(pk=exclusion_id)
    expire_cross_approval_exclusion(exclusion, get_user(settings.SYSTEM_USER))


@app.task(autoretry_for=(Exception,), retry_backoff=True, max_retries=5)
def delete_cross_approval_request_task(request_id, was_approved):
    cross_approval_request = CrossApprovalRequest.objects.filter(
        pk=request_id,
        status="deleting",
    ).first()
    if cross_approval_request is None:
        return

    if was_approved:
        for exclusion in cross_approval_request.exclusions.iterator(chunk_size=100):
            revert_cross_approval_exclusion(
                exclusion,
                exclude_request_id=cross_approval_request.pk,
            )

    with transaction.atomic():
        notify_request_status(
            cross_approval_request,
            "cross_approval_deleted",
            f"Cross-approval request {cross_approval_request.pk} deleted",
        )
        cross_approval_request.delete()


def apply_request_exclusions(request):
    for exclusion in request.exclusions.all():
        transaction.on_commit(
            lambda exclusion_id=exclusion.pk: apply_cross_approval_exclusion.delay(exclusion_id)
        )


def expire_request_exclusions(request):
    for exclusion in request.exclusions.filter(
        expired_at__isnull=True,
        expired_date__lt=timezone.localdate(),
    ):
        expire_cross_approval_exclusion(exclusion, get_user(settings.SYSTEM_USER))


@app.task
def expire_cross_approval_exclusions():
    for exclusion in CrossApprovalExclusion.objects.filter(
        request__status="approved", expired_at__isnull=True, expired_date__lt=timezone.localdate()
    ):
        revert_cross_approval_exclusion_task.delay(exclusion.pk)


@app.task
def check_new_findings_to_cross_approval_exclusion_list():
    exclusions = CrossApprovalExclusion.objects.filter(
        request__status="approved",
        expired_at__isnull=True,
        expired_date__gte=timezone.localdate(),
    )
    for exclusion in exclusions:
        apply_cross_approval_exclusion.delay(exclusion.pk)


def log_status_change(request, user, previous_status, current_status):
    CrossApprovalRequestLog.objects.create(
        request=request,
        changed_by=user,
        previous_status=previous_status,
        current_status=current_status,
    )


def notify_request_status(request, event, title):
    recipients = {request.created_by.username}
    maintainers = get_reviewers_members()
    recipients.update(maintainers)
    create_notification(
        event=event,
        subject=title,
        title=title,
        description=title,
        url=reverse("crossapproval_list"),
        recipients=list(recipients),
    )