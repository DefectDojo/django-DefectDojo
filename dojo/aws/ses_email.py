import json
import logging
import smtplib
import ssl
import boto3
import copy
from email.message import EmailMessage
from botocore.exceptions import ClientError, WaiterError
from dojo.aws.ses_identities import SesIdentity
from dojo.aws.ses_template import SesTemplate
from dojo.aws.ses_generate_smtp_credentials import calculate_key
from django.conf import settings

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


# snippet-end:[python.example_code.ses.SesDestination]


# snippet-start:[python.example_code.ses.SesMailSender]
class SesMailSender:
    """Encapsulates functions to send emails with Amazon SES."""

    def __init__(self, ses_client):
        """
        :param ses_client: A Boto3 Amazon SES client.
        """
        self.ses_client = ses_client

    # snippet-end:[python.example_code.ses.SesMailSender]

    # snippet-start:[python.example_code.ses.SendEmail]
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

    # snippet-end:[python.example_code.ses.SendEmail]

    # snippet-start:[python.example_code.ses.SendTemplatedEmail]
    def send_templated_email(
        self, source, destination, template_name, template_data, reply_tos=None
    ):
        send_args = {
            "Source": source,
            "Destination": destination.to_service_format(),
            "Template": template_name,
            "TemplateData": json.dumps(template_data),
        }
        if reply_tos is not None:
            send_args["ReplyToAddresses"] = reply_tos
        try:
            response = self.ses_client.send_templated_email(**send_args)
            message_id = response["MessageId"]
            logger.info(
                "Sent templated mail %s from %s to %s.",
                message_id,
                source,
                destination.tos,
            )
        except ClientError:
            logger.exception(
                "Couldn't send templated mail from %s to %s.", source, destination.tos
            )
            raise
        else:
            return message_id


def send_email(ses_mail_sender, email):
    logger.debug("send email")
    test_message_text = "Hello from the Amazon SES mail demo!"
    test_message_html = "<p>Hello!</p><p>From the <b>Amazon SES</b> mail demo!</p>"
    ses_mail_sender.send_email(
        email,
        SesDestination([email]),
        "Amazon SES demo",
        test_message_text,
        test_message_html,
    )
    logger.debug("send email succesfully")


def send_email_template(ses_client, ses_mail_sender, email, template):
    logger.debug("send email for template")
    ses_template = SesTemplate(ses_client)
    ses_template.create_template(**template)
    template_data = {"name": email.split("@")[0], "action": "read"}
    ses_mail_sender.send_templated_email(
        email, SesDestination([email]), ses_template.name(), template_data
    )
    if ses_template.template is not None:
        logger.debug("Deleting demo template.")
        ses_template.delete_template()
    logger.debug("send email for template successfully")


def send_email_smtp(email, email_from_address, template):
    logger.debug("send email smtp")
    boto3_session = boto3.Session()
    region = boto3_session.region_name
    credentials = boto3_session.get_credentials()
    port = 587
    smtp_server = f"email-smtp.{region}.amazonaws.com"
    password = calculate_key(credentials.secret_key, region)
    email_template = EmailMessage()
    email_template["From"] = email_from_address
    email_template["To"] = email
    email_template["Subject"] = "¡Enviado desde Vultracker!"
    email_template.set_content(template, subtype="html")
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls(context=context)
        server.login(credentials.access_key, password)
        server.sendmail(email, email, email_template.as_string())
    logger.debug("send email snmtp successfully")
   
    
def get_ses_client():
    logger.debug("get session aws")
    ses_client = boto3.client("ses")
    return ses_client


def get_template(*args, **kwargs):
    template = {
        "name": "1",
        "subject": kwargs.get("subject", "Vultracker notification"),
        "text": kwargs.get("text", "Vultracker SES"),
        "html": kwargs.get("title", ""),
    }
    return template


def aws_ses(email, email_from_address, template):
    try:
        logger.info("Send Email SES")
        send_email_smtp(email, email_from_address, "message the test")
        # ses_client = get_ses_client()
        # ses_mail_sender = SesMailSender(ses_client)
        # send_email(ses_mail_sender=ses_mail_sender, email=email)
        # send_email_template(ses_client=ses_client,
        #                     ses_mail_sender=ses_mail_sender,
        #                     email=email,
        #                     template=template)
    except Exception as e:
        logger.info(f"Error SES: {e}")
