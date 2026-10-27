from dojo.celery import app
from dojo.notifications.helper import create_notification
from dojo.notifications.helper import EmailNotificationManger
from django.core.exceptions import ObjectDoesNotExist
from dojo.api_v2.utils import http_response
from django.core.cache import cache
from django.urls import reverse
from dojo.api_v2.api_error import ApiError 
from dojo.home.helper import encode_string
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.conf import settings
from dojo.models import Risk_Acceptance, Product, Engagement, Finding
from dojo.api_v2.long_risk_acceptance.models import RiskAcceptanceEngagement
from dojo.risk_acceptance.helper import update_or_create_url_risk_acceptance
from dojo.risk_acceptance.notification import Notification as ra_notification
import logging

logger = logging.getLogger(__name__)


@app.task
def send_risk_acceptance_email_task(
        recipients,
        subject,
        message,
        copy_email,
        attachment_data,
        attachment_name,
        attachment_content_type,
        risk_acceptance_id,
        long_risk_acceptance,
        risk_acceptance_eng_id,
        enable_acceptance_risk_for_email,
        template,
        ia_remediation_result,
    ):
    
    try:

        product_type=None
        description=None
        product = None
        risk_pending = None
        risks_evaluation = None
        permission_keys = None
        title = ""
        if risk_acceptance_id:
            risk_pending = get_object_or_404(Risk_Acceptance, pk=risk_acceptance_id)
            risk_pending.accepted_by = recipients
            risk_pending.save()
            product_type = product.prod_type
            product = risk_pending.get_product_type()
            title = f"{risk_pending.TREATMENT_TRANSLATIONS.get(risk_pending.recommendation)} is requested:  {str(risk_pending.engagement.name)}"
        elif risk_acceptance_eng_id:
            risk_pending = get_object_or_404(RiskAcceptanceEngagement, pk=risk_acceptance_eng_id)
            risk_pending.accepted_by = recipients
            product_type = risk_pending.save()
            product = risk_pending.product
            title = f"{product.name} {risk_pending.id}"

    except Exception as e:
        logger.error(str(e))
        raise ApiError.bad_request(f"Risk Acceptance with id {risk_acceptance_id} : {risk_acceptance_eng_id} does not exist.") 


    if long_risk_acceptance:
        long_term = risk_pending.expiration_date.date() - timezone.now().date()
        description=f"requested acceptance <b>long-term</b> of {long_term.days} days for the findings that are part of <b>{product_type}</b> of aplication <b>{product}</b>",

    # Generate Permission Key
    if isinstance(risk_pending, Risk_Acceptance):
        permission_keys = update_or_create_url_risk_acceptance(
            risk_pending,
            send_notification=False)

        create_notification(
            event=template,
            title=title, risk_acceptance=risk_pending,
            subject=subject,
            accepted_findings=risk_pending.accepted_findings.all(),
            reactivated_findings=risk_pending.accepted_findings, engagement=risk_pending.engagement,
            product=risk_pending.engagement.product,
            description=description,
            permission_keys=permission_keys,
            enable_acceptance_risk_for_email=enable_acceptance_risk_for_email,
            recipients=recipients,
            message=message,
            copy_email=copy_email,
            attachment_data=attachment_data,
            attachment_name=attachment_name,
            attachment_content_type=attachment_content_type,
            icon="bell",
            owner=risk_pending.owner,
            color_icon="#A7A40B",
            url=reverse('view_risk_acceptance', args=(risk_pending.engagement.id, risk_pending.id,)),
            ia_remediation_result=ia_remediation_result)
    
    elif isinstance(risk_pending, RiskAcceptanceEngagement):
        create_notification(
            event=template,
            title=title,
            long_risk_acceptance=risk_pending,
            subject=subject,
            description=description,
            permission_keys=permission_keys,
            enable_acceptance_risk_for_email=enable_acceptance_risk_for_email,
            recipients=recipients,
            message=message,
            copy_email=copy_email,
            attachment_data=attachment_data,
            attachment_name=attachment_name,
            attachment_content_type=attachment_content_type,
            icon="bell",
            owner=risk_pending.owner,
            color_icon="#A7A40B",
            url=reverse('view_long_risk_acceptance_details', args=(risk_pending.id,)),
            ia_remediation_result=ia_remediation_result)

def send_report_notification_email(
        event,
        subject,
        title,
        description,
        url,
        recipients,
        icon,
        color_icon,
        ia_remediation_result,
        expiration_time_hours=None,
        product_id=None,
        engagement_id=None,
        finding_id=None
    ):

    notification_kwargs = {
        "event": event,
        "subject": subject,
        "title": title,
        "description": description,
        "url": url,
        "recipients": recipients,
        "icon": icon,
        "color_icon": color_icon,
        "ia_remediation_result": ia_remediation_result,
    }

    if expiration_time_hours:
        notification_kwargs["expiration_time"] = f"{expiration_time_hours} hours"

    encoded_url = encode_string(url)
    key = f"report_finding:{recipients[0]}:{encoded_url}"
    logger.debug(f"REPORT FINDING: calculate key url path {key}")
    expiration_time_seconds = expiration_time_hours * 3600 if expiration_time_hours else None
    cache.set(key, url, expiration_time_seconds)

    notification_kwargs["url"] = f"{settings.SITE_URL}/url_presigned/{encoded_url}"

    try:
        if product_id:
            notification_kwargs["product"] = Product.objects.get(id=product_id)
        if engagement_id:
            notification_kwargs["engagement"] = Engagement.objects.get(id=engagement_id)
        if finding_id:
            notification_kwargs["finding"] = Finding.objects.get(id=finding_id)
    except ObjectDoesNotExist as exc:
        return http_response.bad_request(message=str(exc))

    try:
        create_notification(**notification_kwargs)
        return http_response.ok(message="Report download notification sent successfully")
    except Exception as exc:
        logger.exception("Error sending report download notification")
        return http_response.bad_request(message=f"Error sending notification: {exc}")

@app.task
def send_ia_remediation_notification_email(
        event,
        subject,
        title,
        description,
        url,
        emails,
        icon,
        color_icon,
        ia_remediation_result,
    ):

    notification_kwargs = {
        "event": event,
        "subject": subject,
        "title": title,
        "description": description,
        "url": url,
        "recipient": emails,
        "icon": icon,
        "color_icon": color_icon,
        "ia_remediation_result": ia_remediation_result,
    }

    if ia_remediation_result:
        try:
            EmailNotificationManger().send_mail_notification(**notification_kwargs)
            return http_response.ok(message="Notification sent successfully")
        except Exception as exc:
            logger.exception("Error sending IA remediation notification")
            return http_response.bad_request(message=f"Error sending notification: {exc}")