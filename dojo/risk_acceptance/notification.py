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