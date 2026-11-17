import logging
from contextlib import contextmanager

import pghistory
from dateutil.relativedelta import relativedelta
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Exists, OuterRef, Q, prefetch_related_objects
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import ngettext

from dojo.celery import app
from dojo.jira import services as jira_services
from dojo.models import Dojo_User, Engagement, Finding, Notes, Risk_Acceptance, System_Settings
from dojo.notifications import ticket_comments
from dojo.notifications.helper import create_notification
from dojo.utils import get_full_url, get_system_setting

logger = logging.getLogger(__name__)

# Mirrors the System_Settings.risk_acceptance_form_default_days column default. The column is
# nullable, and get_system_setting() only substitutes its own default when the attribute is
# missing entirely - a null column still returns None - so every caller needs this fallback to
# avoid doing arithmetic with None.
DEFAULT_RISK_ACCEPTANCE_EXPIRATION_DAYS = 180


def expiration_days() -> int:
    """Return the configured expiry window in days, falling back when the setting is unset."""
    configured = get_system_setting("risk_acceptance_form_default_days")
    if configured is None:
        return DEFAULT_RISK_ACCEPTANCE_EXPIRATION_DAYS
    return configured


def default_expiration_date():
    """Return the expiration date a risk acceptance gets when nobody asked for a specific one."""
    return timezone.now() + relativedelta(days=expiration_days())


def engagement_for(risk_acceptance: Risk_Acceptance) -> Engagement | None:
    """
    Return an engagement this risk acceptance can be reached through, or None.

    Prefers the `Engagement.risk_acceptance` link and falls back to the engagement of an
    accepted finding, which is the same derivation `RiskAcceptanceSerializer` uses to attach
    an engagement on create and to repair an orphan on update.
    """
    engagement = risk_acceptance.engagement
    if engagement is not None:
        return engagement

    # iterate rather than .first(), to reuse the accepted_findings prefetch
    accepted_finding = next(iter(risk_acceptance.accepted_findings.all()), None)
    if accepted_finding is not None:
        return accepted_finding.test.engagement

    return None


def engagement_to_notify_about(risk_acceptance: Risk_Acceptance) -> Engagement | None:
    """
    Return an engagement to address a risk acceptance's expiration notification to.

    `Risk_Acceptance.engagement` is a property over `Engagement.risk_acceptance`, a
    many-to-many used as a one-to-many. It is empty for a risk acceptance that was not
    created from an engagement page, which is a supported state rather than corrupt data:
    `RiskAcceptanceSerializer.create` only attaches an engagement when the risk acceptance
    already has findings, `_accept_risks` and the SonarQube status sync never attach one at
    all, and the Pro plugin tracks the association on its own model instead of this relation.

    So fall back to the engagement of an accepted finding - the same derivation
    `RiskAcceptanceSerializer` uses both to attach an engagement on create and to repair an
    orphan on update. Only a risk acceptance with neither an engagement nor any findings has
    nothing to notify about; the notification names a product and links to a per-engagement
    URL, and neither can be produced from an empty risk acceptance.
    """
    engagement = engagement_for(risk_acceptance)
    if engagement is None:
        logger.warning(
            "risk acceptance %i:%s has no engagement and no findings, skipping its expiration notification",
            risk_acceptance.id, risk_acceptance,
        )
    return engagement


def note_on_risk_acceptance(risk_acceptance: Risk_Acceptance, user: Dojo_User | None, action: str, *, reason=None) -> None:
    """
    Record an action taken against the risk acceptance itself.

    Skipped when there is no user: the scheduled expiry job acts on its own behalf and is
    already covered by the expiration notification, so a note authored by nobody adds nothing.
    """
    if user is None:
        return
    risk_acceptance.notes.add(Notes.objects.create(
        entry=(
            f"{Dojo_User.generate_full_name(user)} ({user.id}) {action} this risk acceptance"
            f"{describe_cause(reason=reason)}"
        ),
        author=user,
    ))


def expire_now(risk_acceptance, user=None, reason=None, run=None):
    """
    Expire a risk acceptance now: reactivate its findings if it says so, comment on their tickets and notify.

    :param run: The scheduled run this expiry is part of (see ExpirationRun), which then sends the comments and
        the notification once for the whole run. None sends them now, for this acceptance alone.
    """
    # One transaction, so the acceptance stays locked from the read of its members until it is stamped expired.
    with transaction.atomic():
        reactivated_findings = _expire_now(risk_acceptance, user=user, reason=reason, run=run)
    if reactivated_findings is None:
        return

    # the expiry above is the job here, the notification below is best effort
    engagement = engagement_to_notify_about(risk_acceptance)
    if engagement is None:
        return

    accepted_findings = risk_acceptance.accepted_findings.all()
    title = "Risk acceptance with " + str(len(accepted_findings)) + " accepted findings has expired for " + \
            str(engagement.product) + ": " + str(engagement.name)

    notification = {
        "event": "risk_acceptance_expiration", "title": title, "risk_acceptance": risk_acceptance,
        "accepted_findings": accepted_findings, "reactivated_findings": reactivated_findings, "engagement": engagement,
        "product": engagement.product, "url": reverse("view_risk_acceptance", args=(engagement.id, risk_acceptance.id)),
    }
    if run is None:
        create_notification(**notification)
    else:
        run.notify(notification)


def _expire_now(risk_acceptance, user=None, reason=None, run=None):
    # The acceptance is locked and read again before its members are: a write adding findings to it in another
    # transaction either commits first, and its findings are read and reactivated here, or waits for this expiry
    # and then finds the acceptance expired. Read without the lock (or from the members the caller prefetched),
    # a finding added at that moment stays risk accepted inside an expired acceptance, and nothing visits it again.
    risk_acceptance.refresh_from_db(from_queryset=Risk_Acceptance.objects.select_for_update())
    if risk_acceptance.expiration_date_handled is not None:
        # Expired while this waited for the lock (a manual expire and the scheduled run, or two manual expires):
        # it is not expired a second time, so its date, note, comments and notification are not repeated.
        logger.info("Risk acceptance %i:%s was expired while this expiry waited, nothing to do", risk_acceptance.id, risk_acceptance)
        return None
    prefetch_related_objects([risk_acceptance], *EXPIRATION_PREFETCH)
    logger.info("Expiring risk acceptance %i:%s with %i findings", risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

    reactivated_findings = []
    if risk_acceptance.reactivate_expired:
        for finding in risk_acceptance.accepted_findings.all():
            if not finding.active:  # not sure why this is important
                logger.debug("%i:%s: unaccepting/reactivating finding.", finding.id, finding)
                finding.active = True
                finding.risk_accepted = False

                # Restore Verified so the finding returns to "Active, Verified" rather than
                # keeping the (usually unverified) state it had while risk accepted. Opt-in,
                # because the pre-acceptance verified value is not tracked and some workflows
                # rely on reactivated findings staying unverified until re-triaged.
                if risk_acceptance.restore_verified_expired:
                    finding.verified = True

                # Update any endpoint statuses on each of the findings
                update_endpoint_statuses(finding, accept_risk=False)

                if risk_acceptance.restart_sla_expired:
                    finding.sla_start_date = timezone.now().date()
                # this method both saves and pushed to JIRA (no other post processing)
                finding.save(dedupe_option=False)
                push_to_jira_after_commit(finding, "expiration of risk acceptance")

                reactivated_findings.append(finding)
            else:
                logger.debug("%i:%s already active, no changes made.", finding.id, finding)

        # best effort JIRA integration, no status changes, just a comment, sent once the expiry is committed
        if run is None:
            members = list(risk_acceptance.accepted_findings.all())
            transaction.on_commit(lambda: post_jira_comments(risk_acceptance, members, expiration_message_creator))
        else:
            run.comment(risk_acceptance, risk_acceptance.accepted_findings.all())

    risk_acceptance.expiration_date = timezone.now()
    risk_acceptance.expiration_date_handled = timezone.now()
    risk_acceptance.save()

    note_on_risk_acceptance(risk_acceptance, user, "expired", reason=reason)
    return reactivated_findings


def findings_accepted_elsewhere(risk_acceptance):
    """
    The members of an expired risk acceptance that have been risk accepted some other way since it expired.

    A finding is risk accepted by one acceptance at a time, through its single ``risk_accepted`` flag. When an
    acceptance that reactivates its findings expires, it clears that flag but keeps the findings as members, so
    one of them may be accepted again: in another risk acceptance, or with a simple risk acceptance. A member
    that is risk accepted again belongs to that acceptance now. Without reactivation the members stay risk
    accepted by this acceptance, so only one another unexpired acceptance also lists counts.
    """
    in_another = Risk_Acceptance.objects.filter(
        accepted_findings=OuterRef("pk"),
        expiration_date_handled__isnull=True,
    ).exclude(pk=risk_acceptance.pk)
    held = Q(Exists(in_another))
    if risk_acceptance.reactivate_expired:
        held |= Q(risk_accepted=True)
    return risk_acceptance.accepted_findings.filter(risk_accepted=True).filter(held)


def findings_closed_since_expiry(risk_acceptance):
    """
    The members of an expired risk acceptance that have been closed since it expired.

    An acceptance that reactivates its findings clears their ``risk_accepted`` flag on expiry but keeps them as
    members. Closing one of them afterwards (mitigated, false positive, out of scope, or marked as an inactive
    duplicate) leaves it listed, and reinstating does not accept it again because it is not active. Kept as a
    member, the next expiry would set it active again: its save would clear a mitigation, and a duplicate would
    read active while still a duplicate. Without reactivation the expiry reopens nothing and the members keep
    their flag, so none counts: a member this acceptance never accepted (a duplicate it skipped) stays listed.
    """
    if not risk_acceptance.reactivate_expired:
        return risk_acceptance.accepted_findings.none()
    closed = Q(is_mitigated=True) | Q(false_p=True) | Q(out_of_scope=True) | Q(duplicate=True, active=False)
    return risk_acceptance.accepted_findings.filter(closed, risk_accepted=False)


def reinstate(risk_acceptance, old_expiration_date, user=None, reason=None):
    # One transaction, so the locks below hold until the reinstate is written. The acceptance is locked before its
    # members, the order expire_now takes them in, so a reinstate and an expiry of the same acceptance queue
    # instead of deadlocking.
    with transaction.atomic():
        list(Risk_Acceptance.objects.select_for_update().filter(pk=risk_acceptance.pk).values_list("pk", flat=True))
        _reinstate(risk_acceptance, old_expiration_date, user=user, reason=reason)


def _reinstate(risk_acceptance, old_expiration_date, user=None, reason=None):
    if risk_acceptance.expiration_date_handled:
        # The members are read under a lock, in id order: another write accepting one of them at the same
        # moment waits for this reinstate (or this reinstate for it), so the member is either left out or
        # re-accepted, never both.
        member_ids = list(risk_acceptance.accepted_findings.values_list("id", flat=True))
        list(Finding.objects.select_for_update().filter(id__in=member_ids).order_by("id").values_list("id", flat=True))
        # A member accepted elsewhere since the expiry stays where it is: reinstating would otherwise list it
        # in two acceptances, and expiring or removing either one later would clear the flag the other relies on.
        if accepted_elsewhere := list(findings_accepted_elsewhere(risk_acceptance)):
            logger.info(
                "Reinstating risk acceptance %i:%s leaves out %i findings accepted elsewhere since it expired",
                risk_acceptance.id,
                risk_acceptance,
                len(accepted_elsewhere),
            )
            risk_acceptance.accepted_findings.remove(*accepted_elsewhere)
        # A member closed since the expiry stays closed and leaves too: the next expiry would otherwise reopen it.
        if closed_since := list(findings_closed_since_expiry(risk_acceptance)):
            logger.info(
                "Reinstating risk acceptance %i:%s leaves out %i findings closed since it expired",
                risk_acceptance.id,
                risk_acceptance,
                len(closed_since),
            )
            risk_acceptance.accepted_findings.remove(*closed_since)
        logger.info("Reinstating risk acceptance %i:%s with %i findings", risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

        # The "Reinstate" button has no date to offer and passes the expiration date
        # unchanged, so fall back to the configured default for it. The edit form and
        # the API only reach this point because the caller supplied a new date, which
        # is already on the instance - recomputing the default would throw it away.
        if risk_acceptance.expiration_date == old_expiration_date:
            risk_acceptance.expiration_date = default_expiration_date()

        reinstated_findings = []
        for finding in risk_acceptance.accepted_findings.all():
            if finding.active:
                logger.debug("%i:%s: accepting a.k.a. deactivating finding", finding.id, finding)
                finding.active = False
                finding.risk_accepted = True
                # Update any endpoint statuses on each of the findings
                update_endpoint_statuses(finding, accept_risk=True)
                # this method both saves and pushed to JIRA (no other post processing)
                finding.save(dedupe_option=False)
                push_to_jira_after_commit(finding, "reinstating risk acceptance")
                reinstated_findings.append(finding)
            else:
                logger.debug("%i:%s: already inactive, not making any changes", finding.id, finding)

        # best effort JIRA integration, no status changes, just a comment
        members = list(risk_acceptance.accepted_findings.all())
        transaction.on_commit(lambda: post_jira_comments(risk_acceptance, members, reinstation_message_creator))

        note_on_risk_acceptance(risk_acceptance, user, "reinstated", reason=reason)

    risk_acceptance.expiration_date_handled = None
    risk_acceptance.expiration_date_warned = None
    risk_acceptance.save()


def closed_for_another_reason(finding: Finding) -> bool:
    """
    Whether a finding is closed for a reason other than a risk acceptance: mitigated, false positive or out of scope.

    An acceptance that reactivates its findings clears their ``risk_accepted`` flag on expiry but keeps them as
    members, so a member can be closed afterwards and stay listed. Such a member is not inactive because of the
    acceptance, so taking it out of the acceptance must not reopen it.
    """
    return bool(finding.is_mitigated or finding.mitigated or finding.false_p or finding.out_of_scope)


def release_finding(finding: Finding) -> None:
    """
    Take a risk acceptance off a finding that leaves it, without saving.

    A finding the acceptance held comes back active, and its endpoint statuses with it. A finding closed for another
    reason (see closed_for_another_reason) stays closed with its close fields, and its endpoint statuses only lose
    their risk accepted flag: setting it active would make its save clear the close.
    """
    finding.risk_accepted = False
    if not closed_for_another_reason(finding):
        finding.active = True
        update_endpoint_statuses(finding, accept_risk=False)
        return
    for status in finding.status_finding.filter(risk_accepted=True):
        status.risk_accepted = False
        status.last_modified = timezone.now()
        status.save()


def delete(eng, risk_acceptance):
    # Read the members from the database, not through the acceptance: a caller can hold it with its members prefetched
    # (expire_now prefetches them), and a member closed since then would be judged and saved from that stale copy,
    # reopening it.
    findings = list(Finding.objects.filter(risk_acceptance=risk_acceptance).order_by("id"))
    for finding in findings:
        release_finding(finding)
        finding.save(dedupe_option=False)

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, findings, unaccepted_message_creator)

    risk_acceptance.accepted_findings.clear()
    eng.risk_acceptance.remove(risk_acceptance)
    eng.save()

    risk_acceptance.path.delete()
    risk_acceptance.delete()


def remove_finding_from_risk_acceptance(user: Dojo_User, risk_acceptance: Risk_Acceptance, finding: Finding) -> None:
    logger.debug("removing finding %i from risk acceptance %i", finding.id, risk_acceptance.id)
    risk_acceptance.accepted_findings.remove(finding)
    release_finding(finding)
    # this method both saves and pushed to JIRA (no other post processing)
    finding.save(dedupe_option=False)
    if jira_services.is_push_all_issues(finding) or jira_services.is_keep_in_sync(finding):
        logger.info("pushing finding to JIRA after removal from risk acceptance")
        jira_services.push(finding)

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, [finding], unaccepted_message_creator)
    # Add a note to reflect that the finding was removed from the risk acceptance
    if user is not None:
        finding.notes.add(Notes.objects.create(
            entry=(
                f"{Dojo_User.generate_full_name(user)} ({user.id}) removed this finding from the risk acceptance: "
                f'"{risk_acceptance.name}" ({get_view_risk_acceptance(risk_acceptance)})'
            ),
            author=user,
        ))


def add_findings_to_risk_acceptance(user: Dojo_User, risk_acceptance: Risk_Acceptance, findings: list[Finding]) -> None:
    for finding in findings:
        if not finding.duplicate or finding.risk_accepted:
            finding.active = False
            finding.risk_accepted = True
            finding.save(dedupe_option=False)
            # Update any endpoint statuses on each of the findings
            update_endpoint_statuses(finding, accept_risk=True)

            risk_acceptance.accepted_findings.add(finding)
            push_to_jira_after_commit(finding, "adding to risk acceptance")

        # Add a note to reflect that the finding was removed from the risk acceptance
        if user is not None:
            finding.notes.add(Notes.objects.create(
                entry=(
                    f"{Dojo_User.generate_full_name(user)} ({user.id}) added this finding to the risk acceptance: "
                    f'"{risk_acceptance.name}" ({get_view_risk_acceptance(risk_acceptance)})'
                ),
                author=user,
            ))
    risk_acceptance.save()
    # best effort jira integration, no status changes
    findings = list(findings)
    transaction.on_commit(lambda: post_jira_comments(risk_acceptance, findings, accepted_message_creator))


def push_to_jira_after_commit(finding: Finding, action: str) -> None:
    """
    Push a finding to JIRA once the surrounding transaction commits (right away when there is none).

    The push re-reads the finding, so sent from inside the transaction it could sync the status from
    before the change; and a caller holding row locks would otherwise hold them for the JIRA call.
    """
    if jira_services.is_push_all_issues(finding) or jira_services.is_keep_in_sync(finding):
        logger.info("pushing finding to JIRA after %s", action)
        transaction.on_commit(lambda: jira_services.push(finding))


@app.task
def expiration_handler(*args, **kwargs):
    """
    Expire the risk acceptances past their date, and warn about those expiring within the heads-up window.

    One run sends a bounded number of messages however many acceptances it handles (see ExpirationRun): one
    notification per product and event, and at most one Jira comment per Jira issue and event.
    """
    # Wrap with pghistory context for audit trail
    with pghistory.context(source="risk_acceptance_expiration"):
        try:
            system_settings = System_Settings.objects.get()
        except System_Settings.DoesNotExist:
            logger.warning("Unable to get system_settings, skipping risk acceptance expiration job")
            return

        risk_acceptances = get_expired_risk_acceptances_to_handle()

        logger.info("expiring %i risk acceptances that are past expiration date", len(risk_acceptances))
        expired = ExpirationRun(expiration_message_creator)
        try:
            for risk_acceptance in risk_acceptances:
                with expired.handling(risk_acceptance):
                    expire_now(risk_acceptance, run=expired)
        finally:
            expired.send()

        heads_up_days = system_settings.risk_acceptance_notify_before_expiration
        # blank switches the warning off (the setting says so), as 0 does
        if heads_up_days and heads_up_days > 0:
            risk_acceptances = get_almost_expired_risk_acceptances_to_handle(heads_up_days)

            logger.info("notifying for %i risk acceptances that are expiring within %i days", len(risk_acceptances), heads_up_days)
            warned = ExpirationRun(expiration_warning_message_creator, heads_up_days)
            try:
                for risk_acceptance in risk_acceptances:
                    with warned.handling(risk_acceptance):
                        logger.debug("notifying for risk acceptance %i:%s with %i findings", risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

                        engagement = engagement_to_notify_about(risk_acceptance)
                        if engagement is not None:
                            notification_title = "Risk acceptance with " + str(len(risk_acceptance.accepted_findings.all())) + " accepted findings will expire on " + \
                                timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y") + " for " + \
                                str(engagement.product) + ": " + str(engagement.name)

                            warned.notify({
                                "event": "risk_acceptance_expiration", "title": notification_title, "risk_acceptance": risk_acceptance,
                                "accepted_findings": risk_acceptance.accepted_findings.all(), "engagement": engagement,
                                "product": engagement.product,
                                "url": reverse("view_risk_acceptance", args=(engagement.id, risk_acceptance.id)),
                            })

                        warned.comment(risk_acceptance, risk_acceptance.accepted_findings.all())

                        # marked as warned either way, so a risk acceptance nobody can be notified about
                        # is not re-selected on every subsequent run
                        risk_acceptance.expiration_date_warned = timezone.now()
                        risk_acceptance.save()
            finally:
                warned.send()


def get_view_risk_acceptance(risk_acceptance: Risk_Acceptance) -> str:
    """
    Return the full qualified URL of the view risk acceptance page, or "" if there is none.

    The page is per-engagement, and a risk acceptance does not always have one - see
    `engagement_to_notify_about` for why that is a supported state rather than corrupt data.
    """
    engagement = engagement_for(risk_acceptance)
    if engagement is None:
        return ""
    return get_full_url(
        reverse("view_risk_acceptance", args=(engagement.id, risk_acceptance.id)),
    )


def expiration_message_creator(risk_acceptance, heads_up_days=0):
    return "Risk acceptance [({})|{}] with {} findings has expired".format(
        jira_services.escape_text(risk_acceptance.name),
        get_full_url(reverse("view_risk_acceptance", args=(risk_acceptance.engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_findings.all()))


def expiration_warning_message_creator(risk_acceptance, heads_up_days=0):
    return "Risk acceptance [({})|{}] with {} findings will expire in {} days".format(
        jira_services.escape_text(risk_acceptance.name),
        get_full_url(reverse("view_risk_acceptance", args=(risk_acceptance.engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_findings.all()), heads_up_days)


def reinstation_message_creator(risk_acceptance, heads_up_days=0):
    return "Risk acceptance [({})|{}] with {} findings has been reinstated (expires on {})".format(
        jira_services.escape_text(risk_acceptance.name),
        get_full_url(reverse("view_risk_acceptance", args=(risk_acceptance.engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_findings.all()), timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y"))


def accepted_message_creator(risk_acceptance, heads_up_days=0):
    if risk_acceptance:
        return "Finding has been added to risk acceptance [({})|{}] with {} findings (expires on {})".format(
            jira_services.escape_text(risk_acceptance.name),
            get_full_url(reverse("view_risk_acceptance", args=(risk_acceptance.engagement.id, risk_acceptance.id))),
            len(risk_acceptance.accepted_findings.all()), timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y"))
    return "Finding has been risk accepted"


def unaccepted_message_creator(risk_acceptance, heads_up_days=0):
    if risk_acceptance:
        return "finding was unaccepted/deleted from risk acceptance [({})|{}]".format(jira_services.escape_text(risk_acceptance.name),
            get_full_url(reverse("view_risk_acceptance", args=(risk_acceptance.engagement.id, risk_acceptance.id))))
    return "Finding is no longer risk accepted"


def _ticket_comment_event(message_factory):
    """The ticket comment event a message creator's comment is about, or None for an unknown creator."""
    return {
        accepted_message_creator: ticket_comments.RISK_ACCEPTANCE_ACCEPTED,
        unaccepted_message_creator: ticket_comments.RISK_ACCEPTANCE_UNACCEPTED,
        reinstation_message_creator: ticket_comments.RISK_ACCEPTANCE_REINSTATED,
        expiration_warning_message_creator: ticket_comments.RISK_ACCEPTANCE_EXPIRATION_WARNING,
        expiration_message_creator: ticket_comments.RISK_ACCEPTANCE_EXPIRED,
    }.get(message_factory)


def post_ticket_comments(risk_acceptance, findings, message_factory, heads_up_days=0):
    """
    Hand the comment to the registered ticket comment handlers (see dojo.notifications.ticket_comments).

    Runs before, and apart from, the JIRA project's own setting: each handler decides for its tickets.
    Never raises, so the JIRA comment and the change that caused it go ahead whatever happens here.
    """
    if not ticket_comments.has_ticket_comment_handlers():
        return
    event = _ticket_comment_event(message_factory)
    if event is None:
        return
    try:
        text = message_factory(risk_acceptance, heads_up_days)
    except Exception:
        logger.exception("Could not build the %s ticket comment", event)
        return
    ticket_comments.dispatch_ticket_comments(event, findings, text, risk_acceptance=risk_acceptance)


def post_jira_comment(finding, message_factory, heads_up_days=0):
    if not finding:
        return
    post_ticket_comments(None, [finding], message_factory, heads_up_days)
    if not finding.has_jira_issue and not finding.has_jira_group_issue:
        return
    jira_project = jira_services.get_project(finding)

    if jira_project and jira_project.risk_acceptance_expiration_notification:
        jira_instance = jira_services.get_instance(finding)
        if jira_instance:

            jira_comment = message_factory(None, heads_up_days)

            jira_issue = None
            if finding.has_jira_issue:
                jira_issue = finding.jira_issue
            elif finding.has_jira_group_issue:
                jira_issue = finding.finding_group.jira_issue
            jira_services.add_simple_comment(jira_instance, jira_issue, jira_comment)


def post_jira_comments(risk_acceptance, findings, message_factory, heads_up_days=0):
    if not risk_acceptance:
        return

    if ticket_comments.has_ticket_comment_handlers():
        # read once, for the handlers and the JIRA comments alike
        findings = list(findings)
        post_ticket_comments(risk_acceptance, findings, message_factory, heads_up_days)

    jira_project = jira_services.get_project(risk_acceptance.engagement)

    if jira_project and jira_project.risk_acceptance_expiration_notification:
        jira_instance = jira_services.get_instance(risk_acceptance.engagement)

        if jira_instance:
            jira_comment = message_factory(risk_acceptance, heads_up_days)
            for finding in findings:
                jira_issue = None
                if finding.has_jira_issue:
                    jira_issue = finding.jira_issue
                elif finding.has_jira_group_issue:
                    jira_issue = finding.finding_group.jira_issue

                if jira_issue:
                    jira_services.add_simple_comment(jira_instance, jira_issue, jira_comment)


def _jira_issue_of(finding):
    """The Jira issue a comment about this finding goes on: its own, or its finding group's."""
    if finding.has_jira_issue:
        return finding.jira_issue
    if finding.has_jira_group_issue:
        return finding.finding_group.jira_issue
    return None


class ExpirationRun:

    """
    The comments and notifications one scheduled expiration run owes, sent once at the end of the run.

    Sent as each risk acceptance is handled, a run that expires or warns about many acceptances notifies once per
    acceptance, and comments on a Jira issue once per acceptance holding one of its findings (a finding can sit in
    several acceptances, and the findings of a finding group share one issue). Collected here, the run sends:

    - one notification per product: the usual message when the run handles one acceptance of the product, else a
      digest that lists them all (``risk_acceptances``). Per product rather than one for the whole run, because who
      receives a notification, and so who may read about an acceptance, is decided per product.
    - at most one Jira comment per Jira issue, joining the distinct messages of every acceptance that holds one of
      the issue's findings. Each acceptance's Jira project still decides whether its message is posted.
    - one batch to the ticket comment handlers, each finding with its own text (every acceptance that holds it).
    """

    def __init__(self, message_factory, heads_up_days=0):
        self.message_factory = message_factory
        self.heads_up_days = heads_up_days
        # product id -> the notifications of its acceptances, in the order they were handled
        self._notifications: dict[int, list[dict]] = {}
        # Jira issue id -> [jira instance, jira issue, distinct messages]
        self._jira: dict[int, list] = {}
        # finding id -> [finding, distinct messages], for the ticket comment handlers
        self._tickets: dict[int, list] = {}
        # What the acceptance being handled owes, held until it is handled without error (see handling)
        self._pending: list | None = None

    def _hold(self, apply) -> None:
        if self._pending is None:
            apply()
        else:
            self._pending.append(apply)

    @contextmanager
    def handling(self, risk_acceptance):
        """
        Handle one acceptance of the run on its own: in a savepoint, its messages kept only if it succeeds.

        An acceptance that fails is rolled back, so the next run picks it up again and sends its messages
        then, and logged; the run goes on with the rest, and still sends what they owe.
        """
        self._pending = []
        try:
            with transaction.atomic():
                yield
        except Exception:
            logger.exception("Could not handle risk acceptance %i in this expiration run; the next run tries again", risk_acceptance.id)
            return
        else:
            for apply in self._pending:
                apply()
        finally:
            self._pending = None

    def notify(self, notification: dict) -> None:
        """Hold one acceptance's notification (create_notification's arguments) until the run sends."""
        self._hold(lambda: self._notifications.setdefault(notification["product"].id, []).append(notification))

    def _message(self, risk_acceptance):
        try:
            return self.message_factory(risk_acceptance, self.heads_up_days)
        except Exception:
            logger.exception("Could not build the expiration comment for risk acceptance %i", risk_acceptance.id)
            return None

    @staticmethod
    def _add(messages: list, message: str) -> None:
        if message not in messages:
            messages.append(message)

    def comment(self, risk_acceptance, findings) -> None:
        """Hold the comment one acceptance owes its findings' tickets until the run sends."""
        findings = list(findings)
        if not findings:
            return
        message = None
        if ticket_comments.has_ticket_comment_handlers() and _ticket_comment_event(self.message_factory) is not None:
            message = self._message(risk_acceptance)
            if message is not None:
                for finding in findings:
                    self._hold(lambda finding=finding, message=message: self._add(self._tickets.setdefault(finding.id, [finding, []])[1], message))

        jira_project = jira_services.get_project(risk_acceptance.engagement)
        if not (jira_project and jira_project.risk_acceptance_expiration_notification):
            return
        jira_instance = jira_services.get_instance(risk_acceptance.engagement)
        if not jira_instance:
            return
        message = message or self._message(risk_acceptance)
        if message is None:
            return
        for finding in findings:
            jira_issue = _jira_issue_of(finding)
            if jira_issue:
                self._hold(lambda jira_issue=jira_issue, message=message: self._add(self._jira.setdefault(jira_issue.id, [jira_instance, jira_issue, []])[2], message))

    def _digest(self, notifications: list[dict]) -> dict:
        product = notifications[0]["product"]
        expired = self.message_factory is expiration_message_creator
        count = len(notifications)
        if expired:
            title = ngettext(
                "%(count)s risk acceptance has expired for %(product)s",
                "%(count)s risk acceptances have expired for %(product)s",
                count,
            ) % {"count": count, "product": product}
        else:
            title = ngettext(
                "%(count)s risk acceptance will expire within %(days)s days for %(product)s",
                "%(count)s risk acceptances will expire within %(days)s days for %(product)s",
                count,
            ) % {"count": count, "days": self.heads_up_days, "product": product}
        return {
            "event": "risk_acceptance_expiration",
            "title": title,
            "risk_acceptances": [notification["risk_acceptance"] for notification in notifications],
            # Each acceptance's own link, as its single notification builds it (engagement_to_notify_about),
            # so one with no Engagement link still points at its page.
            "risk_acceptance_rows": [
                {"risk_acceptance": notification["risk_acceptance"], "url": notification["url"]}
                for notification in notifications
            ],
            "expired": expired,
            "product": product,
            "url": reverse("view_product", args=(product.id,)),
        }

    def send(self) -> None:
        """Send what the run collected. Best effort: one failed message is logged and the rest still go."""
        for notifications in self._notifications.values():
            notification = notifications[0] if len(notifications) == 1 else self._digest(notifications)
            try:
                create_notification(**notification)
            except Exception:
                logger.exception("Could not send the risk acceptance expiration notification for %s", notification["product"])
        for jira_instance, jira_issue, messages in self._jira.values():
            try:
                jira_services.add_simple_comment(jira_instance, jira_issue, "\n\n".join(messages))
            except Exception:
                logger.exception("Could not comment on Jira issue %s about expiring risk acceptances", jira_issue.jira_key)
        if self._tickets:
            ticket_comments.dispatch_ticket_comments(
                _ticket_comment_event(self.message_factory),
                [finding for finding, _messages in self._tickets.values()],
                {finding_id: "\n\n".join(messages) for finding_id, (_finding, messages) in self._tickets.items()},
            )
        self._notifications, self._jira, self._tickets = {}, {}, {}


def get_expired_risk_acceptances_to_handle():
    risk_acceptances = Risk_Acceptance.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date__date__lte=timezone.now().date())
    return prefetch_for_expiration(risk_acceptances)


def get_almost_expired_risk_acceptances_to_handle(heads_up_days):
    risk_acceptances = Risk_Acceptance.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date_warned__isnull=True,
            expiration_date__date__lte=timezone.now().date() + relativedelta(days=heads_up_days), expiration_date__date__gte=timezone.now().date())
    return prefetch_for_expiration(risk_acceptances)


# What an expiry reads of an acceptance: its members and their JIRA issues, and its engagement's JIRA project.
EXPIRATION_PREFETCH = (
    "accepted_findings",
    "accepted_findings__jira_issue",
    "engagement_set",
    "engagement__jira_project",
    "engagement__jira_project__jira_instance",
)


def prefetch_for_expiration(risk_acceptances):
    return risk_acceptances.prefetch_related(*EXPIRATION_PREFETCH)


def simple_risk_accept(user: Dojo_User, finding: Finding, *, perform_save=True) -> None:
    if not finding.test.engagement.product.enable_simple_risk_acceptance:
        raise PermissionDenied

    logger.debug("accepting finding %i:%s", finding.id, finding)
    finding.risk_accepted = True
    # risk accepted, so finding no longer considered active
    finding.active = False
    # Update any endpoint statuses on each of the findings
    update_endpoint_statuses(finding, accept_risk=True)
    if perform_save:
        finding.save(dedupe_option=False)
    # post_jira_comment might reload from database so see unaccepted finding. but the comment
    # only contains some text so that's ok
    if jira_services.is_push_all_issues(finding) or jira_services.is_keep_in_sync(finding):
        jira_services.push(finding)

    post_jira_comment(finding, accepted_message_creator)
    # Add a note to reflect that the finding was removed from the risk acceptance
    if user is not None:
        finding.notes.add(Notes.objects.create(
            entry=(f"{Dojo_User.generate_full_name(user)} ({user.id}) has risk accepted this finding"),
            author=user,
        ))


def risk_unaccept(user: Dojo_User, finding: Finding, *, perform_save=True, post_comments=True, reason=None, source=None) -> None:
    """
    Drop a finding's risk acceptance.

    `source` names the mechanism that did it (for example the reimporter closing a fixed
    finding) and `reason` carries free text. Both end up in the note left on the finding,
    which is the only record that survives - the membership row itself is removed.
    """
    logger.debug("unaccepting finding %i:%s if it is currently risk accepted", finding.id, finding)
    if finding.risk_accepted:
        logger.debug("unaccepting finding %i:%s", finding.id, finding)
        # removing from ManyToMany will not fail for non-existing entries
        remove_from_any_risk_acceptance(finding)
        if not finding.mitigated and not finding.false_p and not finding.out_of_scope:
            finding.active = True
        finding.risk_accepted = False
        # Update any endpoint statuses on each of the findings
        update_endpoint_statuses(finding, accept_risk=False)
        if perform_save:
            logger.debug("saving unaccepted finding %i:%s", finding.id, finding)
            finding.save(dedupe_option=False)

        # post_jira_comment might reload from database so see unaccepted finding. but the comment
        # only contains some text so that's ok
        if post_comments:
            post_jira_comment(finding, unaccepted_message_creator)

        # Update the JIRA obect for this finding
        if jira_services.is_push_all_issues(finding) or jira_services.is_keep_in_sync(finding):
            jira_services.push(finding)

        # Add a note to reflect that the finding was removed from the risk acceptance
        if user is not None:
            finding.notes.add(Notes.objects.create(
                entry=(
                    f"{Dojo_User.generate_full_name(user)} ({user.id}) removed a risk exception from this finding"
                    f"{describe_cause(reason=reason, source=source)}"
                ),
                author=user,
            ))


def describe_cause(*, reason=None, source=None) -> str:
    """Render the optional source/reason of an action as a suffix for a note entry."""
    parts = []
    if source:
        parts.append(f"via {source}")
    if reason:
        parts.append(f"reason: {reason}")
    if not parts:
        return ""
    return " (" + ", ".join(parts) + ")"


def remove_from_any_risk_acceptance(finding):
    for r in finding.risk_acceptance_set.all():
        r.accepted_findings.remove(finding)


def update_endpoint_statuses(finding: Finding, *, accept_risk: bool) -> None:
    for status in finding.status_finding.all():
        if accept_risk:
            status.active = False
            status.mitigated = True
            status.risk_accepted = True
        else:
            status.active = True
            status.mitigated = False
            status.risk_accepted = False
        status.last_modified = timezone.now()
        status.save()
