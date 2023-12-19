import logging
from typing import List
from django.conf import settings
from dataclasses import dataclass
from dojo.utils import Response
from django.utils import timezone
from django.urls import reverse
from dojo.models import Engagement, Risk_Acceptance, Finding, Product_Type_Member, Role, Product_Member, \
    Product, Product_Type   
from dojo.risk_acceptance.helper import create_notification, expiration_message_creator, post_jira_comments
from dojo.product_type.queries import get_authorized_product_type_members_for_user
from dojo.product.queries import get_authorized_members_for_product
from dojo.authorization.roles_permissions import Permissions
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


def get_role_members(user, product: Product, product_type: Product_Type):
    user_members: Product_Type_Member = get_authorized_product_type_members_for_user(user, Permissions.Risk_Acceptance)
    if not user_members:
        user_members: Product_Member = get_authorized_members_for_product(product=product, permission=Permissions.Risk_Acceptance)
    if not user_members:
        raise ValueError("The user does not have any product_type or product associated with it")
    for user_member in user_members:
        if user_member.product_type_id == product_type.id:
            return user_member.role.name
    raise ValueError(f"The user is not related to the object {product_type}")    


def role_has_exclusive_permissions(user):
    if user.global_role.role:
        if user.global_role.role.name in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS:
            return True
        return False


def risk_acceptante_pending(
    eng: Engagement, finding: Finding, risk_acceptance: Risk_Acceptance,
    product: Product, product_type: Product_Type
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
        user.is_superuser is True
        or get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
        or number_of_acceptors_required == 0
        or role_has_exclusive_permissions(user)
    ):
        finding.accepted_by = user.username
        risk_accepted_succesfully(eng, finding, risk_acceptance)
        message = "Finding Accept successfully from risk acceptance."
        status = "OK"

    if finding.risk_status in ["Risk Pending", "Risk Rejected"]:
        confirmed_acceptances = get_confirmed_acceptors(finding)
        if is_permissions_risk_acceptance(eng, finding, user, product, product_type):
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
                    risk_accepted_succesfully(eng, finding, risk_acceptance)
                message = "Finding Accept successfully from risk acceptance."
                status = "OK"
            else:
                raise ValueError(
                    f"Error number of acceptors {len(confirmed_acceptances)} > number of acceptors required {number_of_acceptors_required}"
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
    engagement: Engagement, finding: Finding, user, product: Product, product_type: Product_Type
):
    result = False
    if (user.is_superuser is True
        or get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
        or role_has_exclusive_permissions(user)):
        result = True
        
    contacts = get_contacts(engagement, finding.severity, user)
    contacts_ids = [contact.id for contact in contacts]
    if user.id in contacts_ids and finding.risk_accepted is False:
        # has the permissions remove and reject risk pending
        result = True
    return result


def is_rol_permissions_risk_acceptance(user, finding: Finding, product: Product, product_type: Product_Type):
    result = False
    if (
        user.is_superuser is True
        or get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
        or settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(finding.severity).get(
            "number_acceptors"
        )
        == 0
    ):
        result = True
    return result


def rule_risk_acceptance_according_to_critical(severity, user, product: Product, product_type: Product_Type):
    user_rol = get_role_members(user, product, product_type)
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


def limit_assumption_of_vulnerability(*args, **kwargs):
    # "LAV"  - (Limit Assumption of Vulnerability).
    number_of_acceptances_by_finding = Risk_Acceptance.objects.filter(accepted_findings=kwargs["finding_id"]).count()
    result = {}
    if number_of_acceptances_by_finding < settings.LIMIT_ASSUMPTION_OF_VULNERABILITY:
        result["status"] = True
        result["message"] = ""
    else:
        result["status"] = False
        result["message"] = "The finding exceeds the maximum limit of acceptance times"
    return result


def limit_of_tempralily_assumed_vulnerabilities_limited_to_tolerance(*args, **kwargs):
    # "LTVLT - Limit of Temporarily Assumed Vulnerabilities Limited to Tolerance"
    result = {}
    result["status"] = True
    result["message"] = ""
    return result


def percentage_of_vulnerabilitiese_closed(*args, **kwargs):
    # "PVC - Percentage of Vulnerabilities Closed"
    result = {}
    result["status"] = True
    result["message"] = ""
    return result



def temporaly_assumed_vulnerabilities(*args, **kwargs):
    # "TAV - Temporarily Assumed Vulnerabilities"
    result = {}
    result["status"] = True
    result["message"] = ""
    return result



def abuse_control(*args, **kwargs):
    rule_abuse_control = {
        "LAV": limit_assumption_of_vulnerability,
        "LTVLT": limit_of_tempralily_assumed_vulnerabilities_limited_to_tolerance,
        "PVC": percentage_of_vulnerabilitiese_closed,
        "TAV": temporaly_assumed_vulnerabilities
    }
    result_dict = {}
    for key, rule in rule_abuse_control.items():
        result_dict[key] = rule(*args, **kwargs)
    return result_dict


def expire_now_risk_pending(risk_acceptance):
    logger.info('Expiring risk acceptance %i:%s with %i findings', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

    reactivated_findings = []
    if risk_acceptance.reactivate_expired:
        for finding in risk_acceptance.accepted_findings.all():
            if not finding.active:
                logger.debug('%i:%s: unaccepting a.k.a reactivating finding.', finding.id, finding)
                finding.active = True
                finding.risk_accepted = False
                finding.risk_status = "Risk_Active"
                finding.acceptances_confirmed = 0
                finding.accepted_by = ""

                if risk_acceptance.restart_sla_expired:
                    finding.sla_start_date = timezone.now().date()

                finding.save(dedupe_option=False)
                reactivated_findings.append(finding)
                # findings remain in this risk acceptance for reporting / metrics purposes
            else:
                logger.debug('%i:%s already active, no changes made.', finding.id, finding)

        # best effort JIRA integration, no status changes
        post_jira_comments(risk_acceptance, risk_acceptance.accepted_findings.all(), expiration_message_creator)

    risk_acceptance.expiration_date = timezone.now()
    risk_acceptance.expiration_date_handled = timezone.now()
    risk_acceptance.save()

    accepted_findings = risk_acceptance.accepted_findings.all()
    title = 'Risk acceptance with ' + str(len(accepted_findings)) + " accepted findings has expired for " + \
            str(risk_acceptance.engagement.product) + ': ' + str(risk_acceptance.engagement.name)

    create_notification(event='risk_acceptance_expiration', title=title, risk_acceptance=risk_acceptance, accepted_findings=accepted_findings,
                         reactivated_findings=reactivated_findings, engagement=risk_acceptance.engagement,
                         product=risk_acceptance.engagement.product,
                         url=reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id, )))