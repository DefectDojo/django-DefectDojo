import logging
from django.conf import settings
from dojo.user.queries import get_user
from dateutil.relativedelta import relativedelta
from dojo.models import Finding, System_Settings
from dojo.api_v2.api_error import ApiError
from dojo.celery import app
from dojo.api_v2.long_risk_acceptance.models import RiskAcceptanceEngagement 
from dojo.models import Finding, Notes, Risk_Acceptance
from django.utils import timezone
from django.db.models.query import QuerySet
from django.shortcuts import get_object_or_404
from django.db import transaction
from dojo.models import User
from dojo.api_v2.long_risk_acceptance.notifications import Notification 
from django.db.models import Q
logger = logging.getLogger(__name__)

def add_note(event, long_risk_acceptance, system_user):
    note = Notes(
        entry=f"{event}: {long_risk_acceptance.id}",
        author=system_user)
    note.save()
    long_risk_acceptance.notes.add(note)
    note.save()
    return note

def parse_filter_values(filter_string: str) -> list[str]:
    if not filter_string:
        return []
    return [value.strip() for value in filter_string.split(',') if value.strip()]

def apply_dynamic_filter(query: QuerySet[Finding], filter_field: str, filter_values: str) -> QuerySet[Finding]:
    values = parse_filter_values(filter_values)
    if not values:
        return query
    
    q_filter = Q()
    for value in values:
        q_filter |= Q(**{f"{filter_field}__icontains": value})
    
    return query.filter(q_filter)

def to_execute_rule(query: QuerySet[Finding],
                    rules: list[dict],
                    reverse_query: bool
    ) -> QuerySet[Finding]:
    combined_rules_include = Q()
    combined_rules_exclude = Q()
    
    for rule in rules:
        if not rule:
            return query
        
        if rule.filters:
            for field, value in rule.filters.items():
                if isinstance(value, str) and ',' in value:
                    values = parse_filter_values(value)
                    q_filter = Q()
                    for v in values:
                        q_filter |= Q(**{f"{field}__icontains": v})
                    combined_rules_include &= q_filter
                else:
                    combined_rules_include &= Q(**{field: value})
        
        if rule.exclusions:
            for field, value in rule.exclusions.items():
                if isinstance(value, str) and ',' in value:
                    values = parse_filter_values(value)
                    q_filter = Q()
                    for v in values:
                        q_filter |= Q(**{f"{field}__icontains": v})
                    combined_rules_exclude |= q_filter
                else:
                    combined_rules_exclude |= Q(**{field: value})

    if combined_rules_include:
        if not reverse_query:
            query = query.filter(combined_rules_include)
        else:
            query = query.exclude(combined_rules_include) # Query Severse
    
    if combined_rules_exclude:
        if not reverse_query:
            query = query.exclude(combined_rules_exclude)
        else:
            query = query.filter(combined_rules_exclude)
    
    return query

def render_rule(ra_engagement: RiskAcceptanceEngagement, reverse_query: bool = False):
    rules = ra_engagement.riskacceptanceexclusionrule_set.all()
    finding_qr = None
    for eng in ra_engagement.engagement_set.all():
        query = eng.get_all_finding_active
        if finding_qr is None:
            finding_qr = to_execute_rule(query, rules, reverse_query)
        else:
            finding_qr = finding_qr.union(to_execute_rule(query, rules, reverse_query))

    return finding_qr

def get_almost_expired_long_riks_acceptance_to_handle(heads_up_days):
    transfer_finding = RiskAcceptanceEngagement.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date_warned__isnull=True,
            expiration_date__date__lte=timezone.now().date() + relativedelta(days=heads_up_days), expiration_date__date__gte=timezone.now().date())
    return transfer_finding

def apply_review(request, ra_engagement: RiskAcceptanceEngagement):
    ra_engagement.risk_status = "Risks Reviewed"
    ra_engagement.reviewed_by = request.user.username
    ra_engagement.reviewed_date = timezone.now()
    ra_engagement.save()

def active_findings_long_risk_acceptance(finding_qs: QuerySet[Finding]):
    for finding in finding_qs.iterator(chunk_size=200):
        finding.risk_status = "Risk Active"
        finding.active = True
        finding.risk_accepted = False
        finding.save()
        finding.tags.remove("long_term_risk_acceptance")


def _accept_findings(finding_qs: QuerySet[Finding], ra_engagement: Risk_Acceptance):
    """Mark findings as accepted and add long_term_risk_acceptance tag."""
    for finding in finding_qs.iterator(chunk_size=200):
        finding.update_fields(
            risk_status="Risk Accepted",
            active=False,
            risk_accepted=True,
            sla_expiration_date=ra_engagement.expiration_date
        )
        finding.tags.add("long_term_risk_acceptance")
        logger.debug(
            f"finding {finding.id} accepted flow long term risk acceptance "
            f"of engagement {ra_engagement.id}"
        )


def _update_ra_engagement(ra_engagement: RiskAcceptanceEngagement, 
                         update_fields: dict):
    """Update risk acceptance engagement with given fields and save."""
    for field, value in update_fields.items():
        setattr(ra_engagement, field, value)
    ra_engagement.save(update_fields=list(update_fields.keys()))


def _handle_reject(ra_engagement: RiskAcceptanceEngagement, 
                   user, finding_qs: QuerySet[Finding]):
    """Handle reject event."""
    _update_ra_engagement(ra_engagement, {"risk_status": "Risks Rejected"})
    add_note("Long Risk Acceptance Rejected", ra_engagement, user)
    active_findings_long_risk_acceptance(finding_qs)
    Notification.risk_acceptance_rejected(long_risk_acceptance=ra_engagement)


def _handle_expire(ra_engagement: RiskAcceptanceEngagement, 
                   user, finding_qs: QuerySet[Finding]):
    """Handle expire event."""
    _update_ra_engagement(ra_engagement, {"risk_status": "Risks Expired"})
    add_note("Long Risk Acceptance Expired", ra_engagement, user)
    active_findings_long_risk_acceptance(finding_qs)
    Notification.risk_acceptance_expiration(
            event="long_risk_acceptance",
            subject=f"⏳Long Risk Acceptance expired : {ra_engagement.id}🚨",
            description="Long risk acceptance expired",
            long_risk_acceptance=ra_engagement)


def _handle_accept(ra_engagement: RiskAcceptanceEngagement, 
                   user, finding_qs: QuerySet[Finding]):
    """Handle accept event."""
    if ra_engagement.risk_status not in ["Risks Reviewed", "Risks Accepted"]:
        return False
    
    _update_ra_engagement(ra_engagement, {"risk_status": "Risks Accepted"})
    add_note("Long Risk Acceptance Accepted", ra_engagement, user)
    _accept_findings(finding_qs, ra_engagement)
    Notification.risk_acceptance_approved(long_risk_acceptance=ra_engagement)
    return True


def _handle_review(ra_engagement: RiskAcceptanceEngagement, user):
    """Handle review event."""
    _update_ra_engagement(
        ra_engagement,
        {
            "risk_status": "Risks Reviewed",
            "reviewed_by": user.username,
            "reviewed_date": timezone.now(),
        }
    )
    add_note("Long Risk Acceptance Reviewed", ra_engagement, user)
    Notification.risk_acceptance_review(long_risk_acceptance=ra_engagement)


# Map events to handler functions
EVENT_HANDLERS = {
    "reject": _handle_reject,
    "expire": _handle_expire,
    "accept": _handle_accept,
    "review": _handle_review,
}


@app.task
def async_apply_rule_long_risk_acceptance(ra_engagement_id: int, 
                                         user_id: int, 
                                         event: str):
    """Apply rule for long risk acceptance based on event type.
    
    Args:
        ra_engagement_id: ID of RiskAcceptanceEngagement
        user_id: ID of User performing the action
        event: Event type ('reject', 'expire', 'accept', 'review')
    
    Raises:
        ApiError: If no findings found or event is invalid
    """
    ra_engagement = get_object_or_404(RiskAcceptanceEngagement, id=ra_engagement_id)
    user = get_object_or_404(User, id=user_id)
    finding_qs = render_rule(ra_engagement, False)
    
    if not finding_qs:
        raise ApiError(
            f"No findings found for this engagement with the current rules: "
            f"ra_engagement_id {ra_engagement_id}"
        )
    
    handler = EVENT_HANDLERS.get(event)
    if not handler:
        raise ApiError(f"Invalid event type: {event}")
    
    # Review event doesn't need finding_qs
    if event == "review":
        with transaction.atomic():
            handler(ra_engagement, user)
    else:
        with transaction.atomic():
            handler(ra_engagement, user, finding_qs)


def get_expired_long_risk_acceptance_to_handle():
    long_risk_acceptances = RiskAcceptanceEngagement.objects.filter(
        expiration_date__isnull=False,
        expiration_date_handled__isnull=True,
        expiration_date__date__lte=timezone.now().date())
    return long_risk_acceptances

def get_almost_expired_long_risk_acceptance_to_handle(heads_up_days):
    long_risk_acceptances = RiskAcceptanceEngagement.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date_warned__isnull=True,
            expiration_date__date__lte=timezone.now().date() + relativedelta(days=heads_up_days), expiration_date__date__gte=timezone.now().date())
    return long_risk_acceptances

@app.task
def automatic_acceptance(*args, **kwargs):
    queryset = RiskAcceptanceEngagement.objects.filter(risk_status__in=["Risks Accepted"])
    system_user = get_user(settings.SYSTEM_USER)
    for long_risk_acceptance in queryset.iterator(chunk_size=200):
        try:
            async_apply_rule_long_risk_acceptance.apply_async(
                args=(long_risk_acceptance.id, system_user.id, "accept"))
        except Exception as e:
            logger.error(str(e))
            continue
            

def expire_now(long_risk_acceptance: RiskAcceptanceEngagement):
    system_user = get_user(settings.SYSTEM_USER)
    logger.debug(f"Expiration Now {long_risk_acceptance.id}")
    long_risk_acceptance.expiration_date_handled = timezone.now()
    long_risk_acceptance.save()
    long_risk_acceptance_eng = long_risk_acceptance.engagement_set.all()

    for ra_engagement in long_risk_acceptance_eng:
        async_apply_rule_long_risk_acceptance.apply_async(
            args=(ra_engagement.id, system_user.id, "expire"))
      

@app.task
def expiration_handler(*args, **kwargs):
    try:
        system_settings = System_Settings.objects.get()
    except System_Settings.DoesNotExist:
        logger.warning("Unable to get system_settings, skipping risk acceptance expiration job")

    long_risk_acceptances = get_expired_long_risk_acceptance_to_handle()

    logger.info("expiring %i risk acceptances that are past expiration date", len(long_risk_acceptances))
    for long_risk_acceptance in long_risk_acceptances:
        expire_now(long_risk_acceptance)
        # notification created by expire_now code

    heads_up_days = system_settings.risk_acceptance_notify_before_expiration
    if heads_up_days > 0:
        long_risk_acceptances = get_almost_expired_long_risk_acceptance_to_handle(heads_up_days)
        logger.info("notifying for %i long risk acceptances that are expiring within %i days",
                    len(long_risk_acceptances), heads_up_days)
        for long_risk_acceptance in long_risk_acceptances:
            logger.debug("EXPIRATION LONG RISK ACCEPTANCE TASK: "
                         "notifying for long risk acceptance %i",
                         long_risk_acceptance.id)
            Notification.risk_acceptance_expiration(long_risk_acceptance)
            logger.debug(
                            "EXPIRATION LONG RISK ACCEPTANCE TASK: %s "
                            "sending risk acceptance expiration"
                            "warning notification", long_risk_acceptance.id)
            long_risk_acceptance.expiration_date_warned = timezone.now()
            long_risk_acceptance.save()

