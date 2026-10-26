import logging
from django.conf import settings
from rest_framework.generics import GenericAPIView
from dojo.api_v2.utils import http_response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from dojo.user.queries import get_user
from dojo.models import Risk_Acceptance
from dojo.api_v2.notifications.serializers import SerializerEmailNotificationRiskAcceptance
import dojo.api_v2.notifications.helper as notifications_helper
from dojo.api_v2.long_risk_acceptance.models import RiskAcceptanceEngagement
from drf_spectacular.utils import (
    extend_schema,
)
from dojo.api_v2 import (
    permissions,
)
from dojo.notifications.helper import create_notification
logger = logging.getLogger(__name__)

class NotificationEmailApiView(GenericAPIView):
    """
    Endpoint for sending risk acceptance emails asynchronously
    
    Accepts parameters:
        - async: true/false (default: true) - whether to send asynchronously
        - recipient: recipient's email address
        - subject: email subject line
        - template: email template to use
        - message: message body
        - copy: email in copy (optional)
        - attachment: attachment (optional)
        - ia_remediation_result: dictionary or list of dictionaries with IA remediation results (optional)
    """
    permission_classes = (IsAuthenticated, permissions.UserHasPermissionSendEmail,)
    serializer_class = SerializerEmailNotificationRiskAcceptance

    @extend_schema(
        request=SerializerEmailNotificationRiskAcceptance,
        responses={status.HTTP_201_CREATED: SerializerEmailNotificationRiskAcceptance},
    )
    def post(self, request):
        serializer = SerializerEmailNotificationRiskAcceptance(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        event = data.get("event", "risk_acceptance")
        recipients = data.get("recipients")
        emails = data.get("emails")
        title = data.get("title")
        template = data.get("template")
        copy_email = data.get("copy")
        subject = data.get("subject")
        message = data.get("message")
        description = data.get("description")
        url = data.get("url")
        icon = data.get("icon", "download")
        color_icon = data.get("color_icon", "#096C11")
        expiration_time_hours = data.get("expiration_time")
        product_id = data.get("product_id")
        engagement_id = data.get("engagement_id")
        finding_id = data.get("finding_id")
        risk_acceptance_id = data.get("risk_acceptance_id")
        enable_acceptance_risk_for_email = data.get("enable_acceptance_risk_for_email")
        long_risk_acceptance = data.get("long_risk_acceptance")
        attachment = request.FILES.get("attachment")
        risk_acceptance_eng_id = data.get("risk_acceptance_eng_id")
        ia_remediation_result = data.get("ia_remediation_result")

        if event == "ia_remediation_result":
            notifications_helper.send_ia_remediation_notification_email.apply_async(args=(
                event,
                subject,
                title,
                description,
                url,
                emails,
                icon,
                color_icon,
                ia_remediation_result,
            ))
            return http_response.ok(
                        message="Report finding email sent successfully"
                )




        if event == "url_report_finding":
            notifications_helper.send_report_notification_email(
                event=event,
                subject=subject,
                title=title,
                description=description,
                url=url,
                recipients=recipients,
                icon=icon,
                color_icon=color_icon,
                ia_remediation_result=ia_remediation_result,
                expiration_time_hours=expiration_time_hours,
                product_id=product_id,
                engagement_id=engagement_id,
                finding_id=finding_id,
            )
            return http_response.ok(
                message="Report finding email sent successfully"
            )
        
        attachment_data = None
        attachment_name = None
        attachment_content_type = None
        
        if attachment:
            attachment_data = attachment.read()
            attachment_name = attachment.name
            attachment_content_type = attachment.content_type
        
        notifications_helper.send_risk_acceptance_email_task(
            recipients=recipients,
            subject=subject,
            message=message,
            copy_email=copy_email if copy_email else None,
            attachment_data=attachment_data,
            attachment_name=attachment_name,
            attachment_content_type=attachment_content_type,
            risk_acceptance_id=risk_acceptance_id,
            risk_acceptance_eng_id=risk_acceptance_eng_id,
            long_risk_acceptance=long_risk_acceptance,
            enable_acceptance_risk_for_email=enable_acceptance_risk_for_email,
            template=template,
            ia_remediation_result=ia_remediation_result,
        )

        if risk_acceptance_id:
            risk_acceptance = Risk_Acceptance.objects.get(id=risk_acceptance_id)
        elif risk_acceptance_eng_id:
            risk_acceptance = RiskAcceptanceEngagement.objects.get(id=risk_acceptance_eng_id)

            system_user = get_user(settings.SYSTEM_USER)
            risk_acceptance.add_note(
                f"Email notification send to {recipients} successfully, Message: " + (message if message else "No message provided"),
                author=system_user
            )

        return http_response.ok(
            message="Risk acceptance email sent successfully")

