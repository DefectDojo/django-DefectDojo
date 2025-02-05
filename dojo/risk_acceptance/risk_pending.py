import logging
import crum
import json
from dateutil.relativedelta import relativedelta
from dojo.celery import app
from django.utils import timezone
from django.conf import settings
from dojo.utils import Response
from dojo.utils import sla_expiration_risk_acceptance
from dojo.models import (
    Engagement,
    Risk_Acceptance,
    Finding,
    Product_Type_Member,
    Product_Member,
    Product,
    Product_Type,
    System_Settings,
    PermissionKey,
    Dojo_User
    )
from dojo.api_v2.api_error import ApiError
from dojo.risk_acceptance.helper import post_jira_comments, handle_from_provider_risk
from dojo.product_type.helper import get_contacts_product_type_and_product_by_serverity
from dojo.product_type.queries import get_authorized_product_type_members_for_user
from dojo.product.queries import get_authorized_members_for_product
from dojo.authorization.roles_permissions import Permissions
from dojo.risk_acceptance.notification import Notification
from dojo.user.queries import get_role_members
from dojo.risk_acceptance.queries import (
    abuse_control_min_vulnerability_closed,
    abuse_control_max_vulnerability_accepted)
from dojo.transfer_findings import helper as hp_transfer_finding
import dojo.risk_acceptance.helper as ra_helper

logger = logging.getLogger(__name__)


def risk_acceptance_decline(
    eng: Engagement,
    finding: Finding,
    risk_acceptance: Risk_Acceptance
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
        Notification.risk_acceptance_decline(title=title, risk_acceptance=risk_acceptance, finding=finding)
    return Response(status=status, message=message)


def update_expiration_risk_accepted(finding: Finding,
                                    risk_acceptance: Risk_Acceptance):
    finding_accepteds = risk_acceptance.accepted_findings.filter(
        risk_status__in=["Risk Accepted", "Risk Expired"]
        )
    expiration_delta_days = sla_expiration_risk_acceptance('RiskAcceptanceExpiration')

    if (
        len(finding_accepteds) == 0 and
        risk_acceptance.is_expired is False
            ):

        logger.debug(f"Update RiskAcceptanceExpiration: {expiration_delta_days}")
        expiration_date = timezone.now().date() + relativedelta(
            days=expiration_delta_days.get(finding.severity.lower())
            )
        created_date = timezone.now().date()
        risk_acceptance.expiration_date = expiration_date
        risk_acceptance.created = created_date
        risk_acceptance.save()
    return (expiration_delta_days.get(finding.severity.lower()),
            risk_acceptance.expiration_date,
            risk_acceptance.created)

def risk_accepted_succesfully(
    finding: Finding,
    risk_acceptance: Risk_Acceptance,
    send_notification: bool = True,
):
    if not finding.active:
        return True
    finding.risk_status = "Risk Accepted"
    finding.risk_accepted = True
    finding.active = False
    acceptance_days, __, __ = update_expiration_risk_accepted(finding,
                                                              risk_acceptance)
    finding.save()
    ra_helper.handle_from_provider_risk(finding, acceptance_days)

    system_settings = System_Settings.objects.get()
    if system_settings.enable_transfer_finding:
        hp_transfer_finding.close_or_reactive_related_finding(
            event="accepted",
            parent_finding=finding,
            notes=f"temporarily accepted by the parent finding {finding.id} (policies for the transfer of findings)",
            send_notification=False)

    if send_notification:
        title = f"Request is accepted:  {str(risk_acceptance.engagement.product)} : {str(risk_acceptance.engagement.name)}"
        Notification.risk_acceptance_accept(
            title=title,
            risk_acceptance=risk_acceptance,
            finding=finding) 





def role_has_exclusive_permissions(user):
    if hasattr(user, "global_role"):
        if user.global_role.role:
            if user.global_role.role.name in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS:
                return True
    return False


def get_user_with_permission_key(permission_key=None, raise_exception=True) -> Dojo_User:
    if permission_key is None:
        return crum.get_current_user()
    permission_key = PermissionKey.objects.get(token=permission_key)

    if raise_exception and not permission_key.is_active():
        raise ApiError.network_authentication_required(detail="Token is expired")

    user = permission_key.user
    logger.debug(f"User {user} with Permmission key ****")
    return user
    

def rules_for_direct_acceptance(finding: Finding,
                                           product_type: Product_Type,
                                           user: Dojo_User,
                                           product: Product,
                                           risk_acceptance: Risk_Acceptance):
    """Validate if user has permission on risk_acceptance

    Args:
        finding (Finding): finding request permission
        product_type (Product_Type): product_type request permission
        user (Dojo_User): User request permission
        product (Product): Product request permission
        risk_acceptance (Risk_Acceptance):  risk_acceptance request permission
    
    Returns:
        status_permission (dict): Dictionary of status permission of user on risk_acceptance
    """
    number_of_acceptors_required = (
        settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(finding.severity)
        .get("type_contacts")
        .get(
            json.loads(settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[3])[
                product_type.name.split(" - ")[0]
            ]
        ).get("number_acceptors")
    )

    status_permission = {
        "status" : "Failed",
        "message": "Cannot perform action",
        "number_of_acceptors_required": number_of_acceptors_required
    }

    if (
        user.is_superuser is True
        or role_has_exclusive_permissions(user)
        or number_of_acceptors_required == 0
        or get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
        or (finding.impact and finding.impact in settings.COMPLIANCE_FILTER_RISK)
    ):
        finding.accepted_by = user.username
        risk_accepted_succesfully(finding, risk_acceptance)
        status_permission.update(
            {"status": "OK",
             "message": "Finding Accept successfully from risk acceptance.",
             "number_of_acceptors_required": number_of_acceptors_required})
    return status_permission
        

def risk_acceptante_pending(eng: Engagement,
                            finding: Finding,
                            risk_acceptance: Risk_Acceptance,
                            product: Product,
                            product_type: Product_Type,
                            permission_key):
    user = get_user_with_permission_key(permission_key)
    status_permission = rules_for_direct_acceptance(finding,
                                                    product_type,
                                                    user,
                                                    product,
                                                    risk_acceptance)
    message = ""
    if (
        finding.risk_status in ["Risk Pending", "Risk Rejected"]
        and finding.active is True
        and finding.mitigated is None
    ):

        confirmed_acceptances = get_confirmed_acceptors(finding)
        if is_permissions_risk_acceptance(eng, finding, user, product, product_type):
            if user.username in confirmed_acceptances:
                message = "The user has already accepted the risk"
                status_permission["status"] = "Failed"
                return Response(status=status_permission["status"], message=message)
            if len(confirmed_acceptances) < status_permission.get("number_of_acceptors_required"):
                if finding.accepted_by is None or finding.accepted_by == "":
                    finding.accepted_by = user.username
                else:
                    finding.accepted_by += ", " + user.username
                if finding.risk_status == "Risk Rejected":
                    finding.risk_status = "Risk Pending"
                finding.save()
                if status_permission.get("number_of_acceptors_required") == len(
                    get_confirmed_acceptors(finding)
                ):
                    risk_accepted_succesfully(finding, risk_acceptance)
                message = "Finding Accept successfully from risk acceptance."
                status_permission["status"] = "OK"
            else:
                raise ValueError(
                    f"""Error number of acceptors {len(confirmed_acceptances)} > number of acceptors required
                     {status_permission.get("number_of_acceptors_required")}"""
                )
        else:
            raise ApiError.unauthorized(detail="No permissions")
    else:
        message = "The risk is already accepted"

    return Response(status=status_permission["status"], message=message)


def get_confirmed_acceptors(finding: Finding):
    acceptors = []
    if finding.accepted_by:
        acceptors = finding.accepted_by.replace(" ", "").split(",")
    return acceptors


def is_permissions_risk_acceptance(
    engagement: Engagement, finding: Finding, user, product: Product, product_type: Product_Type
):
    if user.is_superuser is True or role_has_exclusive_permissions(user) is True:
        return True

    if finding.mitigated is True or finding.active is False:
        return False

    result = False
    if get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS:
        result = True

    if (
        (finding.impact and finding.impact  in settings.COMPLIANCE_FILTER_RISK)
        and finding.risk_accepted is False
        and len(user.groups.filter(dojo_group__name="Compliance")) > 0
    ):
        result = True

    contacts = get_contacts_product_type_and_product_by_serverity(engagement, finding.severity, user)
    if contacts:
        contacts_ids = [contact.id for contact in contacts]
        if user.id in contacts_ids and finding.risk_accepted is False:
            # has the permissions remove and reject risk pending
            result = True
    return result


def is_rol_permissions_risk_acceptance(user, finding: Finding, product: Product, product_type: Product_Type):
    result = False
    if (
        user.is_superuser is True
        or role_has_exclusive_permissions(user)
        or get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
        or settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(finding.severity).get("type_contacts")
        .get(json.loads(settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[3])[product_type.name.split(" - ")[0]]).get("number_acceptors")
        == 0
    ):
        result = True

    return result


def rule_risk_acceptance_according_to_critical(severity, user, product: Product, product_type: Product_Type):
    user_rol = get_role_members(user, product, product_type)
    risk_rule = settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(severity)
    view_risk_pending = False
    num_acceptors = risk_rule.get("type_contacts").get(json.loads(settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[3])[product_type.name.split(" - ")[0]]).get("number_acceptors")
    if risk_rule:
        if num_acceptors == 0 and user_rol in risk_rule.get(
            "roles"
        ):
            view_risk_pending = False
        elif num_acceptors != 0 and user_rol not in risk_rule.get(
            "roles"
        ):
            view_risk_pending = True
    return view_risk_pending


def limit_assumption_of_vulnerability(**kwargs):
    # "LAV"  - (Limit Assumption of Vulnerability).
    number_of_acceptances_by_finding = Risk_Acceptance.objects.filter(accepted_findings=kwargs["finding_id"], decision=Risk_Acceptance.TREATMENT_ACCEPT).count()
    result = {}
    if number_of_acceptances_by_finding < settings.LIMIT_ASSUMPTION_OF_VULNERABILITY:
        result["status"] = True
        result["message"] = ""
    else:
        result["status"] = False
        result["message"] = f"The finding {kwargs['finding_id']} exceeds the maximum limit of acceptance times"
    return result


def limit_of_tempralily_assumed_vulnerabilities_limited_to_tolerance(**kwargs):
    # "LTVLT - Limit of Temporarily Assumed Vulnerabilities Limited to Tolerance"
    result = {}
    result["status"] = True
    result["message"] = ""
    return result


def percentage_of_vulnerabilitiese_closed(**kwargs):
    """ PVC - Percentage of vulnerabilitiese closed """
    result = kwargs["result"]
    response = abuse_control_min_vulnerability_closed(
        product_id=kwargs["product_id"],
        min_percentage=settings.PERCENTAGE_OF_VULNERABILITIES_CLOSED["percentage"],
        days=settings.PERCENTAGE_OF_VULNERABILITIES_CLOSED["days"])
    logger.debug(f"Abuse Control: {response}")
    if settings.PERCENTAGE_OF_VULNERABILITIES_CLOSED["active"]:
        result = response
    return result


def temporaly_assumed_vulnerabilities(**kwargs):
    """ TAV - Temporarily Assumed Vulnerabilities """
    result = kwargs["result"]
    response = abuse_control_max_vulnerability_accepted(
        product_id=kwargs["product_id"],
        max_percentage=settings.TEMPORARILY_ASSUMED_VULNERABILITIES["percentage"])
    logger.debug(f"Abuse Control: {response}")
    if settings.TEMPORARILY_ASSUMED_VULNERABILITIES["active"]:
        result = response
    return result


def abuse_control(user, finding: Finding, product: Product, product_type: Product_Type):
    result = {}
    result["status"] = True
    result["message"] = ""

    if is_rol_permissions_risk_acceptance(user, finding, product, product_type):
        return {"Privileged role": {"status": True, "message": "This user has risk acceptance privileges"}}

    rule_abuse_control = {
        "LAV": limit_assumption_of_vulnerability,
        "PVC": percentage_of_vulnerabilitiese_closed,
        "TAV": temporaly_assumed_vulnerabilities,
        "LTVLT": limit_of_tempralily_assumed_vulnerabilities_limited_to_tolerance
    }
    result_dict = {}
    for key, rule in rule_abuse_control.items():
        result_dict[key] = rule(finding_id=finding.id, product_id=product.id, result=result)
    return result_dict


def delete(eng, risk_acceptance):
    findings = risk_acceptance.accepted_findings.all()
    for finding in findings:
        finding.active = True
        finding.risk_accepted = False
        finding.accepted_by = ""
        finding.risk_status = "Risk Active"
        finding.save(dedupe_option=False)

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, findings, ra_helper.unaccepted_message_creator)

    risk_acceptance.accepted_findings.clear()
    eng.risk_acceptance.remove(risk_acceptance)
    eng.save()

    for note in risk_acceptance.notes.all():
        note.delete()

    risk_acceptance.path.delete()
    risk_acceptance.delete()

def remove_finding_from_risk_acceptance(risk_acceptance, finding):
    logger.debug('removing finding %i from risk acceptance %i', finding.id, risk_acceptance.id)
    risk_acceptance.accepted_findings.remove(finding)
    finding.active = True
    finding.risk_accepted = False
    finding.accepted_by = ""
    finding.risk_status = "Risk Active"
    finding.save(dedupe_option=False)
    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, [finding], ra_helper.unaccepted_message_creator)


def add_findings_to_risk_pending(risk_pending: Risk_Acceptance, findings):
    for finding in findings:
        ra_helper.add_severity_to_risk_acceptance(risk_pending, finding.severity)
        if not finding.duplicate:
            finding.risk_status = "Risk Pending"
            finding.save(dedupe_option=False)
            risk_pending.accepted_findings.add(finding)
    risk_pending.save()
    Notification.risk_acceptance_request(risk_pending=risk_pending,
                                         enable_acceptance_risk_for_email=settings.ENABLE_ACCEPTANCE_RISK_FOR_EMAIL)
    post_jira_comments(risk_pending, findings, ra_helper.accepted_message_creator)


def risk_unaccept(finding):
    logger.debug('unaccepting finding %i:%s if it is currently risk accepted', finding.id, finding)
    if finding.risk_accepted:
        logger.debug('unaccepting finding %i:%s', finding.id, finding)
        ra_helper.remove_from_any_risk_acceptance(finding)
        if not finding.mitigated and not finding.false_p and not finding.out_of_scope:
            finding.active = True
            finding.risk_accepted = False
            finding.risk_status = "Risk Active"
            finding.acceptances_confirmed = 0
            finding.save()
        ra_helper.post_jira_comment(finding, ra_helper.unaccepted_message_creator)


def accept_or_reject_risk_bulk(eng: Engagement,
                               risk_acceptance: Risk_Acceptance,
                               product: Product,
                               product_type: Product_Type,
                               action,
                               permission_key):
    for accepted_finding in risk_acceptance.accepted_findings.all():
        if action == "accept":
            logger.debug(f"Accepted risk accepted id: {accepted_finding.id}")
            risk_acceptante_pending(
                eng,
                accepted_finding,
                risk_acceptance,
                product,
                product_type,
                permission_key)
        elif action == "reject":
            logger.debug(f"Reject risk accepted id: {accepted_finding.id}")
            risk_acceptance_decline(eng, accepted_finding, risk_acceptance)
        else:
            raise ApiError.forbidden(detail="The parameter *action* must be accept or reject")


def validate_list_findings(conf_risk, type, finding, eng):
    if type == "black_list":
        return next(
            (
                item
                for item in conf_risk.get("BLACK_LIST_FINDING", [])
                if item in finding.vulnerability_ids
                or item == finding.vuln_id_from_tool
            ),
            None,
        )
    elif type == "white_list":
        return next(
            (
                item
                for item in conf_risk.get("WHITE_LIST_FINDING", [])
                if (
                    set(item.get("id")) & set(finding.vulnerability_ids)
                    or finding.vuln_id_from_tool in item.get("id")
                )
                and item.get("where", eng.name) == eng.name
            ),
            None,
        )

@app.task
def expiration_handler(*args, **kwargs):
    if settings.ENABLE_ACCEPTANCE_RISK_FOR_EMAIL is True:
        permission_keys = PermissionKey.objects.filter(
            expiration__date__lte=timezone.now())

        logger.info(
            'expiring %i permission_key that are past expiration date',
            len(permission_keys))

        for permission_key in permission_keys:
            permission_key.expire()
            permission_key.save()
