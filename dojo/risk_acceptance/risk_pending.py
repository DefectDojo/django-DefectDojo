import logging
import crum
from dateutil.relativedelta import relativedelta
from dojo.celery import app
from django.shortcuts import render
from django.db.models import Q
from django.db.models.query import QuerySet
from django.utils import timezone
from django.conf import settings
from dojo.utils import Response
from dojo.utils import sla_expiration_risk_acceptance
from dojo.models import (
    Engagement,
    Risk_Acceptance,
    Finding,
    Product,
    Product_Type,
    System_Settings,
    PermissionKey,
    Dojo_User,
    FindingExclusion,
    GeneralSettings
    )
from dojo.api_v2.api_error import ApiError
from dojo.risk_acceptance.helper import post_jira_comments, get_product_type_prefix_key
from dojo.product_type.helper import get_contacts_product_type_and_product_by_serverity, get_contacts_product_type_and_product
from dojo.group.queries import users_with_permissions_to_approve_long_term_findings
from dojo.risk_acceptance.notification import Notification
from dojo.user.queries import get_role_members, get_user
from dojo.group.queries import get_users_for_group_by_role
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
    if finding.risk_status in ["Risk Accepted", "Risk Pending", "Risk Reviewed"]:
        finding.accepted_by = ""
        finding.reviewed_by = ""
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
    if risk_acceptance.long_term_acceptance:
        finding.tags.add("long_term_risk_acceptance")
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

def user_has_permission_long_risk_acceptance(user, risk_acceptance, product):
    if risk_acceptance and risk_acceptance.long_term_acceptance:
        users = users_with_permissions_to_approve_long_term_findings("Approvers_Risk", "Risk", product),
        users_ids = [user.id for user in users[0]] 
        if user.id in users_ids:
            return True
        return False


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
    
def rules_for_direct_acceptance(
        finding: Finding,
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
        .get(get_product_type_prefix_key(product_type.name)).get("number_acceptors")
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
        finding.risk_status in ["Risk Pending", "Risk Rejected", "Risk Reviewed"]
        and finding.active is True
        and finding.mitigated is None
    ):

        confirmed_acceptances = get_confirmed_acceptors(finding)
        if is_permissions_risk_acceptance(eng, finding, user, product, product_type):
            if risk_acceptance.long_term_acceptance:
                if finding.risk_status == "Risk Pending":
                    finding.risk_status = "Risk Reviewed"
                    finding.reviewed_by = user.username
                    risk_acceptance.reviewed_date = timezone.now()
                    risk_acceptance.save()
                    finding.save()
                    message = "Finding has been marked as reviewed"
                    status_permission["status"] = "OK"
                elif finding.risk_status == "Risk Reviewed" and user_has_permission_long_risk_acceptance(user, risk_acceptance, product):
                    finding.accepted_by = user.username
                    risk_acceptance.accepted_date = timezone.now()
                    risk_acceptance.save()
                    risk_accepted_succesfully(finding, risk_acceptance)
                    message = "Finding Accept successfully from risk acceptance."
                    status_permission["status"] = "OK"


            else:
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

    if finding.mitigated or finding.active is False:
        return False

    # Validate whether the user has permission to accept a risk based on their group membership.
    group_name =  GeneralSettings.get_value("GROUP_REVIEWER_LONGTERM_ACCEPTANCE", "Reviewer_Risk")
    users = get_users_for_group_by_role(group_name, "Risk")
    if user in users and finding.risk_accepted is False:
        return True

    group_name =  GeneralSettings.get_value("GROUP_APPROVERS_LONGTERM_ACCEPTANCE", "Approvers_Risk")
    users = get_users_for_group_by_role(group_name, "Risk")
    if user in users and finding.risk_accepted is False:
        return True
    
    if finding.long_term_acceptance:
        contacts_dict = get_contacts_product_type_and_product(engagement.product)
        for user in contacts_dict.keys():
            return user
        return True

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
        .get(get_product_type_prefix_key(product_type.name)).get("number_acceptors")
        == 0
    ):
        result = True

    return result


def rule_risk_acceptance_according_to_critical(severity, user, product: Product, product_type: Product_Type):
    user_rol = get_role_members(user, product, product_type)
    risk_rule = settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(severity)
    view_risk_pending = False
    num_acceptors = risk_rule.get("type_contacts").get(get_product_type_prefix_key(product_type.name)).get("number_acceptors")
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
    result = {}
    if "is_long_term_acceptance" in kwargs and kwargs["is_long_term_acceptance"] in ["True", True]:
        result["status"] = True
        result["message"] = ""
        return result
    number_of_acceptances_by_finding = Risk_Acceptance.objects.filter(accepted_findings=kwargs["finding_id"], decision=Risk_Acceptance.TREATMENT_ACCEPT).count()
    if number_of_acceptances_by_finding < settings.LIMIT_ASSUMPTION_OF_VULNERABILITY:
        result["status"] = True
        result["message"] = ""
    else:
        result["status"] = False
        result["message"] = f"The finding {kwargs['finding_id']} exceeds the maximum limit of acceptance times"
    return result


def abuse_control(
        user,
        finding: Finding,
        product: Product,
        product_type: Product_Type,
        is_long_term_acceptance: str
    ):
    result = {}
    result["status"] = True
    result["message"] = ""

    if is_rol_permissions_risk_acceptance(user, finding, product, product_type):
        return {"Privileged role": {"status": True, "message": "This user has risk acceptance privileges"}}

    rule_abuse_control = {
        "LAV": limit_assumption_of_vulnerability
    }
    result_dict = {}
    for key, rule in rule_abuse_control.items():
        result_dict[key] = rule(
            finding_id=finding.id,
            product_id=product.id,
            result=result,
            is_long_term_acceptance=is_long_term_acceptance
        )
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
    if risk_acceptance.long_term_acceptance:
        finding.tags.remove("long_term_risk_acceptance")
    finding.active = True
    finding.risk_accepted = False
    finding.accepted_by = ""
    finding.risk_status = "Risk Active"
    finding.save(dedupe_option=False)
    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, [finding], ra_helper.unaccepted_message_creator)


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


def validate_list_findings(type, finding):
    if type == "black_list":
        return next(
            (
                item
                for item in FindingExclusion.objects.filter(
                    type="black_list", status="Accepted").values_list('unique_id_from_tool', flat=True)
                if item in finding.vulnerability_ids
                or item == finding.vuln_id_from_tool
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


def is_correlated(finding_select: Finding,
                  finding_to_correlated: Finding) -> bool:
    """Check if two findings are correlated
    Args:
        finding (Finding): Finding select for user 
        finding_to_correlated (Finding): Finding to check for correlation
    Returns:
        bool: True if the findings are correlated, False otherwise
    """
    result = False
    tags_enabled = GeneralSettings.get_value('ENABLE_TAGS_CORRELATED_FINDINGS')
    if finding_to_correlated.tags.filter(name__in=tags_enabled).exists() is False:
        return result
    if finding_select.severity == finding_to_correlated.severity:
        result = any([
            finding_select.vuln_id_from_tool == finding_to_correlated.vuln_id_from_tool,
            finding_select.vulnerability_ids == finding_to_correlated.vulnerability_ids,
            ])
        if result is True:
            system_user = get_user(settings.SYSTEM_USER)
            finding_to_correlated.add_note(
                note_text=(f"This finding :{finding_to_correlated.id} "
                        f"is correlated the finding: {finding_select.id}"),
                author=system_user)
            logger.debug(
                f"CORRELATED_FINDING: finding {finding_select.id}",
                f"is Correlated to finding {finding_to_correlated.id}: {result}")
    return result


def get_correlated_findings(findings_selected: list[Finding],
                            findings_authorized) -> list[Finding]:
    """Get correlated findings
    Args:
        findings_selected (list[Finding]): List of findings to check for correlation
        finding_authorized (Finding): Finding to check for correlation
    Returns:
        list[Finding]: List of correlated findings
    """
    list_findings_correlated = []
    finding_different_authorized = [
        finding
        for finding in findings_authorized
        if finding not in findings_selected
        ]
    for finding_select in findings_selected:
        for finding_authorized in finding_different_authorized:
            if is_correlated(finding_select, finding_authorized):
                list_findings_correlated.append(finding_authorized)
    return list_findings_correlated


def get_attr_values(objs: list[object] | QuerySet, fields: list[str]):
    """Get a list of attributes from a list of objects
    Args:
        objs (list[object]): List of objects to get attributes from
        fields (list[str]): List of attributes to get from the objects
    Returns:
        dict: Dictionary with attributes as keys and lists of values as values
    """
    result = {}
    for field in fields:
        result[field] = []
        for obj in objs:
            if hasattr(obj, field):
                if field in result.keys():
                    value = getattr(obj, field)
                    if isinstance(value, list):
                        result[field].extend(getattr(obj, field))
                    else:
                        result[field].append(getattr(obj, field))
    return result


def search_finding_correlated(entry_findings: QuerySet[Finding] | list[Finding],
                              engagement: Engagement | int) -> QuerySet:
    """Search for correlated findings in the engagement
    Args:
        entry_findigs (list[Finding]): List of findings to check for correlation
        engagement (Engagement): Engagement container of correlated findings
    Returns:
        queryset: Risk_acceptance queryset with correlated findings
    """
    attrs = get_attr_values(entry_findings, fields=["vuln_id_from_tool", "vulnerability_ids", "id"])
    ids_from_tool = attrs["vuln_id_from_tool"]
    ids_vult = attrs["vulnerability_ids"]
    ids = attrs["id"]
    try:
        if not ids_from_tool and not ids_vult:
            return Risk_Acceptance.objects.none()

        if isinstance(engagement, int) or isinstance(engagement, Engagement):
            tags_enabled = GeneralSettings.get_value('ENABLE_TAGS_CORRELATED_FINDINGS')
            queryset = (
                Risk_Acceptance.objects.filter(
                    engagement=engagement,
                    expiration_date_handled__isnull=True)
                .prefetch_related("accepted_findings")
                .filter(
                    Q(accepted_findings__cve__in=ids_vult) |
                    Q(accepted_findings__vuln_id_from_tool__in=ids_from_tool) &
                    Q(accepted_findings__tags__name__in=tags_enabled) &
                    ~Q(accepted_findings__id__in=ids)
                )
            )
    except Exception as e:
        raise ApiError.internal_server_error(
            detail=f"Error searching for risk acceptance: {e}"
        )
    return queryset


def add_finding_correlated(entry_findings, queryset):
    finding_accepted_ids = []
    tags_enable = GeneralSettings.get_value('ENABLE_TAGS_CORRELATED_FINDINGS')
    for finding in entry_findings:
        risk_acceptance_query = None
        risk_acceptance_query = queryset.filter(
            accepted_findings__cve__in=finding.vulnerability_ids,
            accepted_findings__severity=finding.severity,
            accepted_findings__tags__name__in=tags_enable
            ).order_by("-created")
        if not risk_acceptance_query.exists():
            risk_acceptance_query = queryset.filter(
                accepted_findings__vuln_id_from_tool=finding.vuln_id_from_tool,
                accepted_findings__severity=finding.severity,
                accepted_findings__tags__name__in=tags_enable
                ).order_by("-created")
        # add finding a risk-acceptance
        if risk_acceptance_query:
            logger.debug(
                "CORRELATED_FINDING: adding %i finding to risk acceptance %i",
                finding.id, risk_acceptance_query.first().id)
            finding.add_note(
                note_text=(
                    f"This finding :{finding.id} "
                    f"is correlated whit cve {finding.vulnerability_ids} "
                    f"or vuln_id_from_tool {finding.vuln_id_from_tool}"),
                author=get_user(settings.SYSTEM_USER))
            finding_accepted_ids.append(finding.id)
            ra_helper.add_findings_to_risk_acceptance(
                user=None,
                risk_acceptance=risk_acceptance_query.first(),
                findings=[finding])
    return finding_accepted_ids
