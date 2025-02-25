import logging
import boto3
from botocore.exceptions import ClientError
from dojo.decorators import dojo_async_task, we_want_async

logger = logging.getLogger(__name__)


class SesDestination:
    """Contains data about an email destination."""

    def __init__(self, tos, ccs=None, bccs=None):
        """
        :param tos: The list of recipients on the 'To:' line.
        :param ccs: The list of recipients on the 'CC:' line.
        :param bccs: The list of recipients on the 'BCC:' line.
        """
        self.tos = tos
        self.ccs = ccs
        self.bccs = bccs

    def to_service_format(self):
        """
        :return: The destination data in the format expected by Amazon SES.
        """
        svc_format = {"ToAddresses": self.tos}
        if self.ccs is not None:
            svc_format["CcAddresses"] = self.ccs
        if self.bccs is not None:
            svc_format["BccAddresses"] = self.bccs
        return svc_format


class SesMailSender:
    """Encapsulates functions to send emails with Amazon SES."""

    def __init__(self, ses_client):
        """
        :param ses_client: A Boto3 Amazon SES client.
        """
        self.ses_client = ses_client

    def send_email(self, source, destination, subject, text, html, reply_tos=None):
        send_args = {
            "Source": source,
            "Destination": destination.to_service_format(),
            "Message": {
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": text}, "Html": {"Data": html}},
            },
        }
        if reply_tos is not None:
            send_args["ReplyToAddresses"] = reply_tos
        try:
            response = self.ses_client.send_email(**send_args)
            message_id = response["MessageId"]
            logger.info(
                "Sent mail %s from %s to %s.", message_id, source, destination.tos
            )
        except ClientError:
            logger.exception(
                "Couldn't send mail from %s to %s.", source, destination.tos
            )
            raise
        else:
            return message_id


def send_email(ses_mail_sender, email_from_address, email, subject, message_text, message_html):
    logger.debug("send email")
    
    if isinstance(email, list):
        email_list = email
    else:
        email_list = [email]
        
    
    ses_mail_sender.send_email(
        email_from_address,
        SesDestination(email_list),
        subject,
        message_text,
        message_html,
    )
    logger.debug("send email succesfully")


def get_ses_client():
    logger.debug("get session aws")
    ses_client = boto3.client("ses")
    return ses_client


def get_template(html_content, *args, **kwargs):
    template = {
        "name": kwargs.get("name"),
        "subject": kwargs.get("subject"),
        "text": kwargs.get("text"),
        "html": html_content}
    return template

def aws_ses(email, email_from_address, html_contect, template_name, subject, text):
    template = get_template(html_contect, name=template_name, subject=subject, text=text)
    try:
        ses_client = get_ses_client()
        ses_mail_sender = SesMailSender(ses_client)
        ses_mail_sender = send_email(ses_mail_sender=ses_mail_sender,
                                     email_from_address=email_from_address,
                                     email=email,
                                     subject=subject,
                                     message_text=text,
                                     message_html=template["html"])
        logger.info("Send Email template")
    except Exception as e:
        logger.error(f"Error Send email template: {e}")

