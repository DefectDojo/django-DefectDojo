from dojo.notifications.helper import create_notification
from django.urls import reverse
from dojo.models import Finding, Risk_Acceptance
from crum import get_current_user
from typing import List


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
    def risk_acceptance_request(risk_pending):
        title = f"{risk_pending.TREATMENT_TRANSLATIONS.get(risk_pending.recommendation)} is requested:  {str(risk_pending.engagement.name)}"
        create_notification(event='risk_acceptance_request',
                        title=title, risk_acceptance=risk_pending,
                        subject=f"🙋‍♂️Request of aceptance of risk {risk_pending.id}🙏",
                        accepted_findings=risk_pending.accepted_findings.all(),
                        reactivated_findings=risk_pending.accepted_findings, engagement=risk_pending.engagement,
                        product=risk_pending.engagement.product,
                        description=f"requested acceptance of the risks <b>{risk_pending.name}</b> for the findings",
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
