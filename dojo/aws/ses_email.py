import logging
import boto3
from botocore.exceptions import ClientError
from dojo.decorators import dojo_async_task, we_want_async
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

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


def send_email(
        ses_mail_sender,
        email_from_address,
        email,
        subject,
        message_text,
        message_html,
        copy_email=[],
    ):
    logger.debug("send email")
    if not isinstance(copy_email, list):
        raise Exception("copy_email must be a list")

    if isinstance(email, list):
        email_list = email
    else:
        email_list = [email]
    
    
    ses_mail_sender.send_email(
        email_from_address,
        SesDestination(email_list, ccs=copy_email),
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

def aws_ses(
        email,
        email_from_address,
        html_contect,
        template_name,
        subject,
        text,
        attachment,
        attachment_filename,
        attachment_mimetype,
        copy_email
    ):
    template = get_template(html_contect, name=template_name, subject=subject, text=text)
    try:
        ses_client = get_ses_client()
        ses_mail_sender = SesMailSender(ses_client)
        if attachment_filename:
            ses_mail_sender = send_email_with_attachment(
                ses_mail_sender=ses_mail_sender,
                email_from_address=email_from_address,
                email=email,
                subject=subject,
                message_text=text,
                message_html=template["html"],
                attachment=attachment,
                attachment_filename=attachment_filename,
                attachment_mimetype=attachment_mimetype
            )
        else:
            ses_mail_sender = send_email(
                ses_mail_sender=ses_mail_sender,
                email_from_address=email_from_address,
                email=email,
                subject=subject,
                message_text=text,
                message_html=template["html"],
                copy_email=copy_email
            )
        logger.info("Send Email template")
    except Exception as e:
        logger.error(f"Error Send email template: {e}")

def send_email_with_attachment(
        ses_mail_sender,
        email_from_address,
        email,
        subject,
        message_text,
        message_html,
        attachment,
        attachment_filename,
        attachment_mimetype
    ):
    logger.debug("send email with attachment")
    if isinstance(email, list):
        email_list = email
    else:
        email_list = [email]

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = email_from_address
    msg['To'] = ', '.join(email_list)

    if message_text:
        msg.attach(MIMEText(message_text, 'plain'))
    if message_html:
        msg.attach(MIMEText(message_html, 'html'))

    if attachment and attachment_filename and attachment_mimetype:
        part = MIMEBase(*attachment_mimetype.split('/', 1))
        part.set_payload(attachment)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{attachment_filename}"')
        msg.attach(part)

    ses_client = ses_mail_sender.ses_client
    try:
        response = ses_client.send_raw_email(
            Source=email_from_address,
            Destinations=email_list,
            RawMessage={"Data": msg.as_string()}
        )
        logger.info("Sent mail with attachment from %s to %s.", email_from_address, email_list)
        return response.get("MessageId")
    except ClientError:
        logger.exception("Couldn't send mail with attachment from %s to %s.", email_from_address, email_list)
        raise

