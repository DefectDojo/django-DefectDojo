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
    email_template.set_content(template.get("html"), subtype="html")
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


def get_template(file_path, *args, **kwargs):
    with open(file_path, 'r') as file:
        html_content = file.read()

        template = {
            "name": "1",
            "subject": kwargs.get("subject", "Vultracker notification"),
            "text": kwargs.get("text", "Vultracker SES"),
            "html": """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vultracker</title>
        <style>
            /* Estilos generales */
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f0f4f7;
            }
            .container {
                width: 100%;
                max-width: 600px;
                margin: 0 auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
            }
            /* Estilos del encabezado */
            .header {
                background-color: #3498db;
                color: #ffffff;
                padding: 30px;
                text-align: center;
            }
            /* Estilos del cuerpo del correo */
            .content {
                padding: 30px;
                color: #555555;
            }
            /* Estilos del pie de página */
            .footer {
                background-color: #2980b9;
                color: #ffffff;
                text-align: center;
                padding: 20px;
            }
            /* Estilos del cupón */
            .coupon {
                background-color: #f9f9f9;
                border: 1px solid #cccccc;
                border-radius: 8px;
                padding: 20px;
                text-align: center;
                margin-top: 30px;
            }
            .coupon h2 {
                color: #3498db;
            }
            .coupon p {
                margin-top: 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Encabezado -->
            <div class="header">
                <h1>¡Notification Vultracker!</h1>
            </div>

            <!-- Contenido del correo -->
            <div class="content">
                <p>Hola,</p>
                <p>Se ha generado un evento en tu porduct_type: My proyecto:</p>
                <div class="coupon">
                    <h2><span style="color: green;">Risk Acceptance: 12452cod</span></h2>
                    <p>Developer solicito la aceptacon de la vulnerabilidades "link a vultracker" el dias 12/12/2024: 12:03 pm </p>
                </div>
            </div>

            <!-- Pie de página -->
            <div class="footer">
                <p>© 2024 Devsecops Engine.</p>
            </div>
        </div>
    </body>
    </html>,
        """}
    return template


def aws_ses(email, email_from_address, template):
    try:
        logger.info("Send Email SES")
        send_email_smtp(email, email_from_address, template)
    except Exception as e:
        logger.info(f"Error SES: {e}")
