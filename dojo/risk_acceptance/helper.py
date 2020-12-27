from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


def expire_now(risk_acceptance):
    logger.info('Expiring risk acceptance %i:%s with %i findings', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

    for finding in risk_acceptance.accepted_findings.all():
        logger.debug('unaccepting and reactivating finding %i:%s', finding.id, finding)
        finding.active = True
        finding.save()
        # findings remain in this risk acceptance for reporting / metrics purposes

    # we set the expiration date to now so the findings are no longer seen as 'risk accepted'
    risk_acceptance.expiration_date = timezone.now()
    risk_acceptance.save()


def reinstate(risk_acceptance, old_expiration_date):
    if risk_acceptance.expiration_date > timezone.now() and old_expiration_date <= timezone.now():
        logger.info('Reinstating risk acceptance %i:%s with %i findings', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

        expiration_delta_days = get_system_setting('risk_acceptance_form_default_days', 90)
        risk_acceptance.expiration_date = timezone.now() + relativedelta(expiration_delta_days)

        for finding in risk_acceptance.accepted_findings.all():
            logger.debug('accepting and deactivating finding %i:%s', finding.id, finding)
            finding.active = False
            finding.save()

    risk_acceptance.save()
