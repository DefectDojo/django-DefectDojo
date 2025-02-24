
from typing import List
from django.urls import reverse
from django.conf import settings
from dojo.notifications.helper import create_notification
from dojo.models import Finding, Risk_Acceptance, Dojo_User
from crum import get_current_user


class Notification:

    @staticmethod
    def send_notification(event: str,
                          subject: str,
                          finding: Finding,
                          description: str,
                          user_names: List):

        create_notification(
                event=event,
                subject=subject,
                title=finding.title,
                description=description,
                icon="check-circle",
                color_icon="#096C11",
                recipients=user_names,
                url=reverse('view_finding', args=[str(finding.id)]))

    @staticmethod
    def risk_acceptance_decline(title: str, risk_acceptance: Risk_Acceptance, finding: Finding):

        create_notification(
            event="risk_acceptance_request",
            subject=f"❌Acceptance request rejected in Risk_accepted: {risk_acceptance.id}🔥",
            title=title,
            risk_acceptance=risk_acceptance,
            reactivated_findings=risk_acceptance.accepted_findings,
            engagement=risk_acceptance.engagement,
            product=risk_acceptance.engagement.product,
            description=f"rejected the request for acceptance of finding <b>{finding.title}</b> with id <b>{finding.id}</b>",
            owner=get_current_user(),
            icon="times-circle",
            color_icon="#B90C0C",
            recipients=[risk_acceptance.owner.get_username()],
            url=reverse(
                "view_risk_acceptance",
                args=(
                    risk_acceptance.engagement.id,
                    risk_acceptance.id,
                ),
            ),
        )

    @staticmethod
    def risk_acceptance_accept(title: str, risk_acceptance: Risk_Acceptance, finding: Finding):
        create_notification(
            event="risk_acceptance_request",
            subject=f"✅Acceptance request confirmed in Risk_Accepted: {risk_acceptance.id}👌",
            title=title,
            risk_acceptance=risk_acceptance,
            reactivated_findings=risk_acceptance.accepted_findings,
            engagement=risk_acceptance.engagement,
            product=risk_acceptance.engagement.product,
            description=f"accepted the request of finding <b>{finding.title}</b> with id <b>{finding.id}</b>",
            owner=risk_acceptance.accepted_by.replace("[", "").replace("]", "").replace("'", "").replace(",", " and"),
            icon="check-circle",
            color_icon="#096C11",
            recipients=[risk_acceptance.owner.get_username()],
            url=reverse(
                "view_risk_acceptance",
                args=(
                    risk_acceptance.engagement.id,
                    risk_acceptance.id,
                ),
            ),
        )
    
    @staticmethod
    def risk_acceptance_request(*args, **kwargs):
        risk_pending = kwargs["risk_pending"]
        product = risk_pending.engagement.product
        product_type = product.prod_type
        enable_acceptance_risk_for_email= kwargs["enable_acceptance_risk_for_email"]
        permission_keys = kwargs.get("permission_keys", None)
        title = f"{risk_pending.TREATMENT_TRANSLATIONS.get(risk_pending.recommendation)} is requested:  {str(risk_pending.engagement.name)}"
        description=f"requested acceptance of the risks <b>{risk_pending.name}</b> for the findings that are part of <b>{product_type}</b> of aplication <b>{product}</b>",
        create_notification(event='risk_acceptance_request',
                        title=title, risk_acceptance=risk_pending,
                        subject=f"🙋‍♂️Request of aceptance of risk {risk_pending.id}🙏",
                        accepted_findings=risk_pending.accepted_findings.all(),
                        reactivated_findings=risk_pending.accepted_findings, engagement=risk_pending.engagement,
                        product=risk_pending.engagement.product,
                        description=description,
                        permission_keys=permission_keys,
                        enable_acceptance_risk_for_email=enable_acceptance_risk_for_email,
                        recipients=eval(risk_pending.accepted_by),
                        icon="bell",
                        owner=risk_pending.owner,
                        color_icon="#1B30DE",
                        url=reverse('view_risk_acceptance', args=(risk_pending.engagement.id, risk_pending.id, )))

    @staticmethod
    def risk_acceptance_expiration(risk_acceptance,
                                   reactivated_findings=None,
                                   title=None):
        accepted_findings = risk_acceptance.accepted_findings.all()
        if title is None:
            title = 'Risk acceptance with ' + str(len(accepted_findings)) + " accepted findings has expired for " + \
                    str(risk_acceptance.engagement.product) + ': ' + str(risk_acceptance.engagement.name)

        create_notification(
            event='risk_acceptance_expiration',
            subject=f"⚠️Acceptance request Risk_Acceptance: {risk_acceptance.id} has expired🔔",
            title=title, risk_acceptance=risk_acceptance, accepted_findings=accepted_findings,
            reactivated_findings=reactivated_findings, engagement=risk_acceptance.engagement,
            product=risk_acceptance.engagement.product,
            url=reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id, )))
    
    @staticmethod
    def proccess_confirmation(risk_pending: Risk_Acceptance, user_leader: Dojo_User,  error:str = "", product="", product_type=""):
        """sends notification depending on the event 
       

        Args:
            risk_pending (Risk_Acceptance): Riks Acceptance Object
            event (str): accepted, reject, No permissions, generic, Token is expired
            error (str): Description of error
        """
        rule_event_mapping={
            "accept": {
                "title":"The <strong>acceptance</strong> process has been successfully completed for the risk acceptance with ID: {risk_pending.id}",
                "description": "You have <strong>accepted</strong> temporary the following findings:",
                "subject": f"✅Acceptance process completed successfully for Risk_Accepted ID: {risk_pending.id}👌",
                "icon":"check-circle",
                "color_icon":"#096C11",
                "recipients": [user_leader.username]
                },
            "reject": {
                "title": f"The <strong>Reject</strong< process has been successfully completed for the risk acceptance with ID: {risk_pending.id}",
                "description": "You have <strong>Reject</strong> request acceptance for the following findings:",
                "subject": f"✅The Reject process completed successfully for Risk_Accepted id: {risk_pending.id}👌",
                "icon": "check-circle",
                "color_icon": "#096C11",
                "recipients": [user_leader.username]
                },
            "The user does not have any product_type or product associated with it": {
                "title": "You do not have permission to the product_type",
                "description": f"You do not have permission on the product_type <strong>{product_type}</strong> or on the product <strong>{product}</storng> , please contact the devsecops team ",
                "subject": f"⚠️ Warning, You do not have permission to the product_type  Risk_Acceptance ID: {risk_pending.id}🔔",
                "icon":"check-circle",
                "color_icon": "#b97a0c",
                "recipients": [user_leader.username]
            },
            "Token is expired": {
                "title": "An error occurred in the acceptance process, Url has expired",
                "description": f"""The acceptance URL has expired, more than {int(settings.LIFETIME_HOURS_PERMISSION_KEY/24)} days passed since this URL was created.
                    <strong>{risk_pending.owner.get_short_name()}</strong> must refresh the URL in Vultracker so you can continue with the acceptance process""",
                "subject": f"❌ Error, The acceptance process was not completed Risk_Acceptance ID: {risk_pending.id}🔔",
                "icon": "check-circle",
                "color_icon": "#B90C0C",
                "recipients": [user_leader.username, risk_pending.owner.username]
            },
            "generic": {
                "title": "An error occurred in the acceptance process",
                "description": f"An error occurred in the acceptance or rejection process please contact the devsecops team. detail error : {error}",
                "subject": f"❌ Error, The acceptance process was not completed  Risk_Acceptance ID: {risk_pending.id}🔔",
                "icon": "check-circle",
                "color_icon": "#B90C0C",
                "recipients": [user_leader.username]
            }
        }
        event_mapping = rule_event_mapping.get(error, rule_event_mapping["generic"])

        create_notification(
            event="risk_acceptance_confirmed",
            subject=event_mapping["subject"],
            title=event_mapping["title"],
            risk_acceptance=risk_pending,
            reactivated_findings=risk_pending.accepted_findings,
            engagement=risk_pending.engagement,
            product=risk_pending.engagement.product,
            description=event_mapping["description"],
            icon=event_mapping["icon"],
            color_icon=event_mapping["color_icon"],
            recipients=event_mapping["recipients"],
            url=reverse(
                "view_risk_acceptance",
                args=(
                    risk_pending.engagement.id,
                    risk_pending.id,
                ),
            ),
        )