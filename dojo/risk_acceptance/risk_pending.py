import logging
from typing import List
from django.conf import settings
from dataclasses import dataclass
from dojo.utils import Response
from django.urls import reverse
from dojo.models import Engagement, Risk_Acceptance, Finding
from dojo.risk_acceptance.helper import create_notification
import crum

logger = logging.getLogger(__name__)


def risk_acceptance_decline(
    eng: Engagement, finding: Finding, risk_acceptance: Risk_Acceptance
):
    status = "Failed"
    message = "Cannot perform action"
    if finding.risk_status == "Risk Rejected":
        status = "Failed"
        message = "Risk is already rejected"
    if finding.risk_status in ["Risk Accepted", "Risk Pending"]:
        finding.accepted_by = ""
        finding.active = True
        finding.risk_accepted = False
        finding.risk_status = "Risk Rejected"
        finding.save()
        status = "OK"
        message = "Risk Rejected"
        title = f"Rejected request:  {str(risk_acceptance.engagement.product)} : {str(risk_acceptance.engagement.name)}"
        create_notification(
            event="risk_acceptance_request",
            title=title,
            risk_acceptance=risk_acceptance,
            accepted_findings=risk_acceptance.accepted_findings,
            reactivated_findings=risk_acceptance.accepted_findings,
            engagement=risk_acceptance.engagement,
            product=risk_acceptance.engagement.product,
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
    return Response(status=status, message=message)


def risk_accepted_succesfully(
    eng: Engagement,
    finding: Finding,
    risk_acceptance: Risk_Acceptance,
    send_notification: bool = True,
):
    finding.risk_status = "Risk Accepted"
    finding.risk_accepted = True
    finding.active = False
    finding.save()
    # Send notification
    if send_notification:
        title = f"Request is accepted:  {str(risk_acceptance.engagement.product)} : {str(risk_acceptance.engagement.name)}"
        create_notification(
            event="risk_acceptance_request",
            title=title,
            risk_acceptance=risk_acceptance,
            accepted_findings=risk_acceptance.accepted_findings,
            reactivated_findings=risk_acceptance.accepted_findings,
            engagement=risk_acceptance.engagement,
            product=risk_acceptance.engagement.product,
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


def risk_acceptante_pending(
    eng: Engagement, finding: Finding, risk_acceptance: Risk_Acceptance
):
    user = crum.get_current_user()
    status = "Failed"
    message = "Cannot perform action"
    number_of_acceptors_required = (
        settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(finding.severity).get(
            "number_acceptors"
        )
    )
    if (
        user.is_superuser
        or user.global_role.role.name in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
        or number_of_acceptors_required == 0
    ):
        finding.accepted_by = user.username
        risk_accepted_succesfully(eng, finding, risk_acceptance)
        message = "Finding Accept successfully from risk acceptance."
        status = "OK"

    if finding.risk_status in ["Risk Pending", "Risk Rejected"]:
        confirmed_acceptances = get_confirmed_acceptors(finding)
        if is_permissions_risk_acceptance(eng, finding, user):
            if user.username in confirmed_acceptances:
                message = "The user has already accepted the risk"
                status = "Failed"
                return Response(status=status, message=message)
            if len(confirmed_acceptances) < number_of_acceptors_required:
                if finding.accepted_by is None or finding.accepted_by == "":
                    finding.accepted_by = user.username
                else:
                    finding.accepted_by += ", " + user.username
                if finding.risk_status == "Risk Rejected":
                    finding.risk_status = "Risk Pending"
                finding.save()
                if number_of_acceptors_required == len(
                    get_confirmed_acceptors(finding)
                ):
                    # TODO : MOVER este bloque de codigo al evento save del findign
                    risk_accepted_succesfully(eng, finding, risk_acceptance)
                message = "Finding Accept successfully from risk acceptance."
                status = "OK"
            else:
                raise ValueError(
                    f"Error number of accepttors{finding.acceptances_confirmed} \
                                    < number of acceptors required {number_of_acceptors_required}"
                )
    else:
        message = "The risk is already accepted"

    return Response(status=status, message=message)


def get_confirmed_acceptors(finding: Finding):
    acceptors = []
    if finding.accepted_by:
        acceptors = finding.accepted_by.replace(" ", "").split(",")
    return acceptors


def get_contacts(engagement: Engagement, finding_serverity: str, user):
    rule = settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(finding_serverity)
    product_type = engagement.product.get_product_type
    contacts = rule.get("type_contacts")

    get_contacts_dict = {
        "product_type_manager": product_type.product_type_manager,
        "product_type_technical_contact": product_type.product_type_technical_contact,
        "environment_manager": product_type.environment_manager,
        "environment_technical_contact": product_type.environment_technical_contact,
    }
    contact_list = []
    for contact in contacts:
        if contact in get_contacts_dict.keys():
            if not get_contacts_dict[contact]:
                logger.warning("Risk_pending: contact not related to a product_type")
            contact_list.append(get_contacts_dict[contact])
        else:
            raise ValueError(f"Contact {contact} not found")
    if contact_list == []:
        contact_list.append(user)

    return contact_list


def is_permissions_risk_acceptance(
    engagement: Engagement, finding: Finding, user
):
    if user.is_superuser is True or user.global_role.role.name in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS:
        return True
    contacts = get_contacts(engagement, finding.severity, user)
    contacts_ids = [contact.id for contact in contacts]
    if user.id in contacts_ids and finding.risk_accepted is False:
        # has the permissions remove and reject risk pending
        return True
    return False


def is_rol_permissions_risk_acceptance(user, severity):
    result = False
    if (
        user.is_superuser is True
        or user.global_role.role.name in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
        or settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(severity).get(
            "number_acceptors"
        )
        == 0
    ):
        result = True
    return result


def rule_risk_acceptance_according_to_critical(severity, request):
    if request.user.global_role.role is None:
        raise ValueError("The user does not have a role associated")
    user_rol = request.user.global_role.role.name
    risk_rule = settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(severity)
    view_risk_pending = False
    if risk_rule:
        if risk_rule.get("number_acceptors") == 0 and user_rol in risk_rule.get(
            "roles"
        ):
            view_risk_pending = False
        elif risk_rule.get("number_acceptors") != 0 and user_rol not in risk_rule.get(
            "roles"
        ):
            view_risk_pending = True
    return view_risk_pending
