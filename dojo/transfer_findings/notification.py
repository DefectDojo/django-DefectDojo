from dojo.notifications.helper import create_notification
from django.urls import reverse
from dojo.models import Finding, TransferFinding
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
    def transfer_finding_request(transfer_finding: TransferFinding):
        title = f"{transfer_finding.title[:30]} Acceptance"
        pid = transfer_finding.origin_product.id
        create_notification(
            event='transfer_finding',
            title=title,
            transfer_finding=transfer_finding,
            subject=f"🙋‍♂️Acceptance request for transfer-finding: {transfer_finding.id}🙏",
            product=transfer_finding.destination_product,
            description=f"Acceptance request for <b>{transfer_finding.title}</b> for the findings:",
            recipients=[transfer_finding.accepted_by.get_username()],
            icon="check-circle",
            color_icon="#096C11",
            owner=transfer_finding.owner,
            url=reverse("view_transfer_finding", args=(pid,)))

    
    @staticmethod
    def transfer_finding_status_changes(transfer_finding: TransferFinding):
        title = f"{transfer_finding.title[:30]} Status"
        pid = transfer_finding.origin_product.id
        create_notification(
            event='transfer_finding',
            title=title,
            transfer_finding=transfer_finding,
            subject=f"🙋‍♂️Changes in the transfer-finding: {transfer_finding.id}🙏",
            accepted_findings=transfer_finding.transfer_findings.all(),
            product=transfer_finding.destination_product,
            description=f"Changes <b>{transfer_finding.title}</b> for the findings",
            recipients=[transfer_finding.owner.get_username()],
            icon="check-circle",
            color_icon="#b97a0c",
            owner=transfer_finding.owner,
            url=reverse("view_transfer_finding", args=(pid,)))


    @staticmethod
    def transfer_finding_remove(transfer_finding: TransferFinding):
        title = f"{transfer_finding.title[:30]} Remove"
        pid = transfer_finding.origin_product.id
        create_notification(
            event='transfer_finding',
            title=title,
            transfer_finding=transfer_finding,
            subject=f"🗑️Transfer-finding has been removed : {transfer_finding.id}❌",
            accepted_findings=transfer_finding.transfer_findings.all(),
            product=transfer_finding.destination_product,
            description=f"Transfer-finding has been removed <b>{transfer_finding.title}</b> for the findings",
            recipients=[transfer_finding.owner.get_username()],
            icon="times-circle",
            color_icon="#B90C0C",
            owner=transfer_finding.owner,
            url=reverse("view_transfer_finding", args=(pid,)))

    @staticmethod
    def transfer_finding_finding_remove(transfer_finding: TransferFinding):
        title = f"{transfer_finding.title[:30]} Remove"
        pid = transfer_finding.origin_product.id
        create_notification(
            event='transfer_finding',
            title=title,
            transfer_finding=transfer_finding,
            subject=f"🗑️Transfer-finding has been removed : {transfer_finding.id}❌",
            accepted_findings=transfer_finding.transfer_findings.all(),
            product=transfer_finding.destination_product,
            description=f"Transfer-finding has been removed <b>{transfer_finding.title}</b> for the findings",
            recipients=[transfer_finding.owner.get_username()],
            icon="times-circle",
            color_icon="#B90C0C",
            owner=transfer_finding.owner,
            url=reverse("view_transfer_finding", args=(pid,)))
