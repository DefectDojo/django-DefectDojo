import logging
from django.conf import settings
from dojo.utils import Response
from django.utils import timezone
from dateutil.relativedelta import relativedelta
from dojo.utils import sla_expiration_risk_acceptance
from django.urls import reverse
from dojo.models import Engagement, Risk_Acceptance, Finding, Product_Type_Member, Role, Product_Member, \
    Product, Product_Type, TransferFindingFinding
from dojo.risk_acceptance.helper import create_notification, expiration_message_creator, post_jira_comments
from dojo.product_type.queries import get_authorized_product_type_members_for_user
from dojo.product.queries import get_authorized_members_for_product
from dojo.authorization.roles_permissions import Permissions
import dojo.risk_acceptance.helper as ra_helper
import crum
import json

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
            subject=f"❌Acceptance request rejected in Risk_accepted: {risk_acceptance.id}🔥",
            title=title,
            risk_acceptance=risk_acceptance,
            reactivated_findings=risk_acceptance.accepted_findings,
            engagement=risk_acceptance.engagement,
            product=risk_acceptance.engagement.product,
            description=f"rejected the request for acceptance of finding <b>{finding.title}</b> with id <b>{finding.id}</b>",
            owner=crum.get_current_user(),
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

def update_expiration_risk_accepted(finding: Finding):
    expiration_delta_days = sla_expiration_risk_acceptance('RiskAcceptanceExpiration')
    logger.debug(f"Update RiskAcceptanceExpiration: {expiration_delta_days}")
    expiration_date = timezone.now().date() + relativedelta(days=expiration_delta_days.get(finding.severity.lower()))
    created_date = timezone.now().date()
    return expiration_delta_days.get(finding.severity.lower()), expiration_date, created_date

def risk_acceptd_findings_related(finding):
    # obtener los findings relacionados con un queryset
    transfer_findings_finding = TransferFindingFinding.objects.filter(finding_related=finding.id) 
    for transfer_finding_finding in transfer_findings_finding:
        origin_finding = transfer_finding_finding.findings 
        
def handle_from_provider_risk(finding, acceptance_days):
    tag = ra_helper.get_matching_value(list_a=finding.tags.tags, list_b=[settings.PROVIDER1, settings.PROVIDER2, settings.PROVIDER3])
    if tag is not None:
        if tag.name == settings.PROVIDER3:
            finding_id = finding.unique_id_from_tool
        else:
            finding_id = finding.vuln_id_from_tool
        ra_helper.risk_accept_provider(
            finding_id=finding_id,
            provider=tag.name,
            acceptance_days=acceptance_days,
            url=settings.PROVIDER_URL,
            header=settings.PROVIDER_HEADER,
            token=settings.PROVIDER_TOKEN)

def risk_accepted_succesfully(
    user,
    eng: Engagement,
    finding: Finding,
    risk_acceptance: Risk_Acceptance,
    send_notification: bool = True,
):
    if not finding.active:
        return True
    finding.risk_status = "Risk Accepted"
    finding.risk_accepted = True
    finding.active = False
    acceptance_days, expiration_date, created_date = update_expiration_risk_accepted(finding)
    handle_from_provider_risk(finding, acceptance_days)
    risk_acceptance.expiration_date = expiration_date
    risk_acceptance.created = created_date
    risk_acceptance.save()
    finding.save()
    # Send notification
    if send_notification:
        title = f"Request is accepted:  {str(risk_acceptance.engagement.product)} : {str(risk_acceptance.engagement.name)}"
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


def get_role_members(user, product: Product, product_type: Product_Type):
    user_members = None
    user_members_product_type: Product_Type_Member = get_authorized_product_type_members_for_user(user, Permissions.Risk_Acceptance)
    user_members = list(user_members_product_type)
    user_members_product: Product_Member = get_authorized_members_for_product(product=product, permission=Permissions.Risk_Acceptance)
    if user_members_product:
        user_members += list(user_members_product)
    if not user_members:
        raise ValueError("The user does not have any product_type or product associated with it")
    for user_member in user_members:
        if hasattr(user_member,"product_type_id"):
            if user_member.product_type_id == product_type.id:
                return user_member.role.name
        elif hasattr(user_member, "product_id"):
            if user_member.product_id == product.id:
                return user_member.role.name
    raise ValueError(f"The user is not related to the object {product_type}")    


def role_has_exclusive_permissions(user):
    if hasattr(user, "global_role"):
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
        settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(finding.severity)
        .get("type_contacts")
        .get(
            json.loads(settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[3])[
                product_type.name.split(" - ")[0]
            ]
        ).get("number_acceptors")
    )
    if (
        user.is_superuser is True
        or role_has_exclusive_permissions(user)
        or number_of_acceptors_required == 0
        or get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS
    ):
        finding.accepted_by = user.username
        risk_accepted_succesfully(user, eng, finding, risk_acceptance)
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
                    risk_accepted_succesfully(user, eng, finding, risk_acceptance)
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
    contacts = rule.get("type_contacts").get(json.loads(settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[3])[product_type.name.split(" - ")[0]]).get("users")

    get_contacts_dict = {
        "team_manager": engagement.product.team_manager,
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
            else:
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
        or role_has_exclusive_permissions(user)
        or get_role_members(user, product, product_type) in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS):
        result = True
        
    contacts = get_contacts(engagement, finding.severity, user)
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
    # "PVC - Percentage of Vulnerabilities Closed"
    result = {}
    result["status"] = True
    result["message"] = ""
    return result


def temporaly_assumed_vulnerabilities(**kwargs):
    # "TAV - Temporarily Assumed Vulnerabilities"
    result = {}
    result["status"] = True
    result["message"] = ""
    return result


def abuse_control(user, finding: Finding, product: Product, product_type: Product_Type):
    if is_rol_permissions_risk_acceptance(user, finding, product, product_type):
        return {"Privileged role": {"status": True, "message": "This user has risk acceptance privileges"}}

    rule_abuse_control = {
        "LAV": limit_assumption_of_vulnerability,
        "LTVLT": limit_of_tempralily_assumed_vulnerabilities_limited_to_tolerance,
        "PVC": percentage_of_vulnerabilitiese_closed,
        "TAV": temporaly_assumed_vulnerabilities
    }
    result_dict = {}
    for key, rule in rule_abuse_control.items():
        result_dict[key] = rule(finding_id=finding.id)
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
    title = f"{risk_pending.TREATMENT_TRANSLATIONS.get(risk_pending.recommendation)} is requested:  {str(risk_pending.engagement.name)}"
    create_notification(event='risk_acceptance_request',
                        subject=f"🙋‍♂️Request of aceptance of risk {risk_pending.id}🙏",
                        title=title, risk_acceptance=risk_pending,
                        accepted_findings=risk_pending.accepted_findings,
                        reactivated_findings=risk_pending.accepted_findings, engagement=risk_pending.engagement,
                        product=risk_pending.engagement.product,
                        recipients=eval(risk_pending.accepted_by),
                        description=f"requested acceptance of risk for finding {finding.title} with id {finding.id}",
                        owner=risk_pending.owner,
                        icon="bell",
                        color_icon="#1B30DE",
                        url=reverse('view_risk_acceptance', args=(risk_pending.engagement.id, risk_pending.id, )))
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


def accept_risk_pending_bullk(eng, risk_acceptance, product, product_type):
    for accepted_finding in risk_acceptance.accepted_findings.all():
        logger.debug(f"Accepted risk accepted id: {accepted_finding.id}")
        risk_acceptante_pending(eng, accepted_finding, risk_acceptance, product, product_type)

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
