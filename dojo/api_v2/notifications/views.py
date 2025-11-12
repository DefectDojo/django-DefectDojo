import logging
from rest_framework.generics import GenericAPIView
from dojo.api_v2.utils import http_response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
from dojo.risk_acceptance.helper import update_or_create_url_risk_acceptance
from dojo.api_v2.notifications.serializers import SerializerEmailNotificationRiskAcceptance
from drf_spectacular.utils import (
    extend_schema,
)
from dojo.api_v2 import (
    permissions,
)
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
    """
    permission_classes = (IsAuthenticated, permissions.UserHasPermissionSendEmail,)
    serializer_class = SerializerEmailNotificationRiskAcceptance

    @extend_schema(
        request=SerializerEmailNotificationRiskAcceptance,
        responses={status.HTTP_201_CREATED: SerializerEmailNotificationRiskAcceptance},
    )
    def post(self, request):
        serializer = SerializerEmailNotificationRiskAcceptance(data=request.data)
        if serializer.is_valid():
            recipients = serializer.validated_data.get('recipients')
            template = serializer.validated_data.get('template')
            copy_email = serializer.validated_data.get('copy', '')
            subject = serializer.validated_data.get('subject')
            message = serializer.validated_data.get('message')
            is_async = serializer.validated_data.get('is_async')
            risk_acceptance_id = serializer.validated_data.get('risk_acceptance_id')
            enable_acceptance_risk_for_email = serializer.validated_data.get('enable_acceptance_risk_for_email')
            attachment = request.FILES.get('attachment')
        else:
            return http_response.bad_request(serializer.errors)
        
        attachment_data = None
        attachment_name = None
        attachment_content_type = None
        
        if is_async and attachment:
            attachment_data = attachment.read()
            attachment_name = attachment.name
            attachment_content_type = attachment.content_type
        


        if is_async:
            logger.info(f"Sending risk acceptance emails asynchronously to {recipients}")
            
            from dojo.api_v2.notifications.helper import send_risk_acceptance_email_task
            task = send_risk_acceptance_email_task.apply_async(
                args=(recipients,subject,message,copy_email,attachment_data,attachment_name,attachment_content_type),
            )
            
            return http_response.ok(
                message=f"Risk acceptance email is being sent asynchronously task id {task.id}")
        
        else:
            logger.info(f"Sending risk acceptance emails synchronously to {recipients}")
            
            from dojo.api_v2.notifications.helper import send_risk_acceptance_email_task
            send_risk_acceptance_email_task(
                recipients=recipients,
                subject=subject,
                message=message,
                copy_email=copy_email if copy_email else None,
                attachment_data=attachment_data,
                attachment_name=attachment_name,
                attachment_content_type=attachment_content_type,
                risk_acceptance_id=risk_acceptance_id,
                enable_acceptance_risk_for_email=enable_acceptance_risk_for_email,
                template=template,
            )
            
            return http_response.ok(
                message="Risk acceptance email sent successfully")
