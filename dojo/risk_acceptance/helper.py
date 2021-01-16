from django.utils import timezone
from dojo.utils import get_system_setting, get_full_url
from dateutil.relativedelta import relativedelta
import dojo.jira_link.helper as jira_helper
from dojo.jira_link.helper import escape_for_jira
from dojo.notifications.helper import create_notification
from django.urls import reverse
from celery.decorators import task
from dojo.models import System_Settings, Risk_Acceptance, Finding
import logging

logger = logging.getLogger(__name__)


def expire_now(risk_acceptance):
    logger.info('Expiring risk acceptance %i:%s with %i findings', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

    reactivated_findings = []
    if risk_acceptance.reactivate_expired:
        for finding in risk_acceptance.accepted_findings.all():
            if not finding.active:
                logger.debug('%i:%s: unaccepting a.k.a reactivating finding.', finding.id, finding)
                finding.active = True
                if risk_acceptance.restart_sla_expired:
                    finding.sla_start_date = timezone.now().date()

                if finding.has_jira_issue:
                    jira_helper.add_simple_jira_comment(jira_instance, finding.jira_issue, jira_comment)

                finding.save(dedupe_option=False)
                reactivated_findings.append(finding)
                # findings remain in this risk acceptance for reporting / metrics purposes
            else:
                logger.debug('%i:%s already active, no changes made.', finding.id, finding)

        # best effort JIRA integration, no status changes
        post_jira_comments(risk_acceptance, risk_acceptance.accepted_findings.all(), expiration_message_creator)

    risk_acceptance.expiration_date = timezone.now()
    risk_acceptance.expiration_date_handled = timezone.now()
    risk_acceptance.save()

    accepted_findings = risk_acceptance.accepted_findings.all()
    title = 'Risk acceptance with ' + str(len(accepted_findings)) + " accepted findings has expired for " + \
            str(risk_acceptance.engagement.product) + ': ' + str(risk_acceptance.engagement.name)

    create_notification(event='risk_acceptance_expiration', title=title, risk_acceptance=risk_acceptance, accepted_findings=accepted_findings,
                         reactivated_findings=reactivated_findings, engagement=risk_acceptance.engagement,
                         product=risk_acceptance.engagement.product,
                         url=reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id, )))


def reinstate(risk_acceptance, old_expiration_date):
    if risk_acceptance.expiration_date_handled:
        logger.info('Reinstating risk acceptance %i:%s with %i findings', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

        expiration_delta_days = get_system_setting('risk_acceptance_form_default_days', 90)
        risk_acceptance.expiration_date = timezone.now() + relativedelta(days=expiration_delta_days)

        reinstated_findings = []
        for finding in risk_acceptance.accepted_findings.all():
            if finding.active:
                logger.debug('%i:%s: accepting a.k.a. deactivating finding', finding.id, finding)
                finding.active = False
                finding.save(dedupe_option=False)
                reinstated_findings.append(finding)
            else:
                logger.debug('%i:%s: already inactive, not making any changes', finding.id, finding)

        # best effort JIRA integration, no status changes
        post_jira_comments(risk_acceptance, risk_acceptance.accepted_findings.all(), reinstation_message_creator)

    risk_acceptance.expiration_date_handled = None
    risk_acceptance.expiration_date_warned = None
    risk_acceptance.save()


def delete(eng, risk_acceptance):
    findings = risk_acceptance.accepted_findings.all()
    for finding in findings:
        finding.active = True
        finding.save(dedupe_option=False)

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, findings, unaccepted_message_creator)

    risk_acceptance.accepted_findings.clear()
    eng.risk_acceptance.remove(risk_acceptance)
    eng.save()

    for note in risk_acceptance.notes.all():
        note.delete()

    risk_acceptance.path.delete()
    risk_acceptance.delete()


def remove_finding_from_risk_acceptance(risk_acceptance, finding):
    logger.debug('removing finding %i from risk acceptance %i', finding.id, risk_acceptance.id)
    risk_acceptance.accepted_findings.remove(finding)
    finding.active = True
    finding.save(dedupe_option=False)
    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, [finding], unaccepted_message_creator)


def add_findings_to_risk_acceptance(risk_acceptance, findings):
    for finding in findings:
        if finding.active:
            finding.active = False
            finding.save(dedupe_option=False)
        risk_acceptance.accepted_findings.add(finding)
    risk_acceptance.save()

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, findings, accepted_message_creator)


@task(name='risk_acceptance_expiration_handler')
def expiration_handler(*args, **kwargs):
    """
    Creates a notification upon risk expiration and X days beforehand if configured.
    This notification is 1 per risk acceptance.

    If configured also sends a JIRA comment in both case to each jira issue.
    This is per finding.
    """

    try:
        system_settings = System_Settings.objects.get()
    except System_Settings.DoesNotExist:
        logger.warn("Unable to get system_settings, skipping risk acceptance expiration job")

    risk_acceptances = get_expired_risk_acceptances_to_handle()

    logger.info('expiring %i risk acceptances that are past expiration date', len(risk_acceptances))
    for risk_acceptance in risk_acceptances:
        expire_now(risk_acceptance)
        # notification created by expire_now code

    heads_up_days = system_settings.risk_acceptance_notify_before_expiration
    if heads_up_days > 0:
        risk_acceptances = get_almost_expired_risk_acceptances_to_handle(heads_up_days)

        logger.info('notifying for %i risk acceptances that are expiring within %i days', len(risk_acceptances), heads_up_days)
        for risk_acceptance in risk_acceptances:
            logger.debug('notifying for risk acceptance %i:%s with %i findings', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

            notification_title = 'Risk acceptance with ' + str(len(risk_acceptance.accepted_findings.all())) + " accepted findings will expire on " + \
                timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y") + " for " + \
                str(risk_acceptance.engagement.product) + ': ' + str(risk_acceptance.engagement.name)

            create_notification(event='risk_acceptance_expiration', title=notification_title, risk_acceptance=risk_acceptance,
                                accepted_findings=risk_acceptance.accepted_findings.all(), engagement=risk_acceptance.engagement,
                                product=risk_acceptance.engagement.product,
                                url=reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id, )))

            post_jira_comments(risk_acceptance, expiration_warning_message_creator, heads_up_days)

            risk_acceptance.expiration_date_warned = timezone.now()
            risk_acceptance.save()


def expiration_message_creator(risk_acceptance, heads_up_days=0):
    return 'Risk acceptance [(%s)|%s] with %i findings has expired' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_findings.all()))


def expiration_warning_message_creator(risk_acceptance, heads_up_days=0):
    return 'Risk acceptance [(%s)|%s] with %i findings will expire in %i days' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_findings.all()), heads_up_days)


def reinstation_message_creator(risk_acceptance, heads_up_days=0):
    return 'Risk acceptance [(%s)|%s] with %i findings has been reinstated (expires on %s)' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_findings.all()), timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y"))


def accepted_message_creator(risk_acceptance, heads_up_days=0):
    return 'Finding has been added to risk acceptance [(%s)|%s] with %i findings (expires on %s)' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_findings.all()), timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y"))


def unaccepted_message_creator(risk_acceptance, heads_up_days=0):
    return 'finding was unaccepted/deleted from risk acceptance [(%s)|%s]' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id))))


def post_jira_comments(risk_acceptance, findings, message_factory, heads_up_days=0):
    jira_project = jira_helper.get_jira_project(risk_acceptance.engagement)
    logger.debug("1")

    if jira_project and jira_project.risk_acceptance_expiration_notification:
        logger.debug("2")
        jira_instance = jira_helper.get_jira_instance(risk_acceptance.engagement)

        if jira_instance:
            logger.debug("3")
            jira_comment = message_factory(risk_acceptance, heads_up_days)

            for finding in findings:
                logger.debug("4")
                if finding.has_jira_issue:
                    logger.debug("Creating JIRA comment for something risk acceptance related")
                    jira_helper.add_simple_jira_comment(jira_instance, finding.jira_issue, jira_comment)


def get_expired_risk_acceptances_to_handle():
    risk_acceptances = Risk_Acceptance.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date__date__lte=timezone.now().date())
    return prefetch_for_expiration(risk_acceptances)


def get_almost_expired_risk_acceptances_to_handle(heads_up_days):
    risk_acceptances = Risk_Acceptance.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date_warned__isnull=True,
            expiration_date__date__lte=timezone.now().date() + relativedelta(days=heads_up_days), expiration_date__date__gte=timezone.now().date())
    return prefetch_for_expiration(risk_acceptances)


def prefetch_for_expiration(risk_acceptances):
    return risk_acceptances.prefetch_related('accepted_findings', 'accepted_findings__jira_issue',
                                                'engagement_set',
                                                'engagement__jira_project',
                                                'engagement__jira_project__jira_instance'
                                             )


# gets or creates the simple risk acceptance instance connected to the engagement. only contains this finding if it is simple accepted
def get_simple_risk_acceptance(finding, create=True):
    # check if has test, if not, return False to avoid errors on test being None later on. This can happen when creating a finding from a template
    if not hasattr(finding, 'test'):
        return None

    if hasattr(finding.test.engagement, 'simple_risk_acceptance') and len(finding.test.engagement.simple_risk_acceptance) > 0:
        return finding.test.engagement.simple_risk_acceptance[0]

    simple_risk_acceptance = finding.test.engagement.risk_acceptance.filter(name=Finding.SIMPLE_RISK_ACCEPTANCE_NAME).prefetch_related('accepted_findings').first()
    if simple_risk_acceptance is None and create:
        from dojo.utils import get_current_user
        user = get_current_user()
        simple_risk_acceptance = Risk_Acceptance.objects.create(
                owner=user if user else User.objects.first(),
                name=Finding.SIMPLE_RISK_ACCEPTANCE_NAME,
                decision=Risk_Acceptance.TREATMENT_ACCEPT,
                decision_details='These findings are accepted using a simple risk acceptance without expiration date, '
                'approval document or compensating control information. Unaccept and use full risk acceptance if you '
                'need to have more control over those fields.'
        )
        self.test.engagement.risk_acceptance.add(simple_risk_acceptance)
    return simple_risk_acceptance


def simple_risk_accept(finding):
    # adding to ManyToMany will not cause duplicate entries
    risk_acceptance = get_simple_risk_acceptance(finding)
    risk_acceptance.accepted_findings.add(finding)
    # risk accepted, so finding no longer considered active
    finding.active = False
    finding.save(dedupe_option=False)
    post_jira_comments(risk_acceptance, [finding], accepted_message_creator)


def risk_unaccept(finding):
    logger.debug('unaccepting finding')
    # removing from ManyToMany will not fail for non-existing entries
    risk_acceptance = finding.active_risk_acceptance
    print(vars(risk_acceptance))
    logger.debug('active risk acceptance: %i:%s', risk_acceptance.id, risk_acceptance)
    get_simple_risk_acceptance(finding).accepted_findings.remove(finding)
    # risk acceptance no longer in place, so reactivate, but only when it makes sense

    # for now also remove from any other risk acceptance as differianting between simple and full here would clutter the menu.
    # also currently you can only add a finding to 1 risk acceptance, so this would only affect old findings added to multiple
    # risk acceptances in some obcure way
    remove_from_any_risk_acceptance(finding)
    if not finding.mitigated and not finding.false_p and not finding.out_of_scope and not finding.risk_acceptance_set.exists():
        finding.active = True
        finding.save(dedupe_option=False)

    logger.debug('posting comments for unaccept')
    post_jira_comments(risk_acceptance, [finding], unaccepted_message_creator)


def remove_from_any_risk_acceptance(finding):
    for r in finding.risk_acceptance_set.all():
        r.accepted_findings.remove(finding)

# @property
# def is_simple_risk_accepted(finding):

#     if finding.get_simple_risk_acceptance(create=False) is not None:
#         return finding.get_simple_risk_acceptance().accepted_findings.filter(id=finding.id).exists()
#         # print('exists: ', exists)
#         # return exists

#     return False
