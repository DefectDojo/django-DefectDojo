from dojo.celery import app
from django.core.mail import EmailMessage
from dojo.notifications.helper import create_notification
from django.urls import reverse
from dojo.api_v2.api_error import ApiError 
from django.utils import timezone
from django.conf import settings
from dojo.models import Risk_Acceptance
from dojo.aws import ses_email
from dojo.models import System_Settings
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
        enable_acceptance_risk_for_email,
        permission_keys,
        template,
    ):
    
    try:
        risk_pending = Risk_Acceptance.objects.get(id=risk_acceptance_id)
    except Risk_Acceptance.DoesNotExist:
        logger.error(f"Risk Acceptance with id {risk_acceptance_id} does not exist.")
        return ApiError.bad_request(f"Risk Acceptance with id {risk_acceptance_id} does not exist.") 

    product = risk_pending.engagement.product
    product_type = product.prod_type
    title = f"{risk_pending.TREATMENT_TRANSLATIONS.get(risk_pending.recommendation)} is requested:  {str(risk_pending.engagement.name)}"
    long_term = risk_pending.expiration_date.date() - timezone.now().date()
    description=f"requested acceptance <b>long-term</b> of {long_term.days} days for the findings that are part of <b>{product_type}</b> of aplication <b>{product}</b>",
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
        url=reverse('view_risk_acceptance', args=(risk_pending.engagement.id, risk_pending.id,)))