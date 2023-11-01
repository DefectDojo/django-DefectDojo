import logging
from typing import List
from django.conf import settings
from dataclasses import dataclass
from utils.response import Response
from django.urls import reverse
from dojo.models import Engagement, Risk_Acceptance, Finding
from dojo.risk_acceptance.helper import create_notification
import dojo.risk_acceptance.risk_pending as rp_helper
import crum
logger = logging.getLogger(__name__)


def finding_is_black_list():
    pass


def get_abuse_control():
    # se calcula el control de abuso
    pass


def get_number_acceptance_risk(finding):
    # TODO: number acceptaciones 
    return 1



def risk_acceptante_pending(eng: Engagement, finding: Finding, risk_acceptance: Risk_Acceptance):
    user = crum.get_current_user()
    status = "Failed"
    message = "Cannot perform action"
    for finding in risk_acceptance.accepted_findings.all():
        if finding.risk_pending:
            if is_permissions_risk_accept(eng, finding.severity, user):
                number_of_acceptors_required = settings.RULE_RISK_ACCEPTANCE_ACCORDING_TO_CRITICALITY\
                    .get(finding.severity).get("number_acceptors")
                if finding.acceptances_confirmed == number_of_acceptors_required:
                    logger.warning("All necessary acceptances have already been made")
                    message = "All necessary acceptances have already been made"
                    break
                if finding.acceptances_confirmed < number_of_acceptors_required:
                    finding.acceptances_confirmed += 1
                    if finding.accepted_by is None:
                        finding.accepted_by = user.username
                    else:
                        if user.username in finding.accepted_by:
                            logger.warning("User already accepts the risk")
                            message = "User already accepts the risk"
                            break
                        finding.accepted_by += ", " + user.username
                    message = "Finding Accept successfully from risk acceptance."
                    status = "OK"
                    finding.save()
                    if finding.acceptances_confirmed == number_of_acceptors_required:
                        finding.risk_pending = False
                        finding.risk_accepted = True
                        finding.active = False
                        finding.save()
                        # Send notification
                        title = f"Request is accepted:  {str(risk_acceptance.engagement.product)} : {str(risk_acceptance.engagement.name)}"
                        create_notification(event='risk_acceptance_request', title=title, risk_acceptance=risk_acceptance, accepted_findings=risk_acceptance.accepted_findings,
                        reactivated_findings=risk_acceptance.accepted_findings, engagement=risk_acceptance.engagement,
                        product=risk_acceptance.engagement.product,
                        recipients=[risk_acceptance.owner.get_username()],
                        url=reverse('view_risk_acceptance', args=(risk_acceptance.engagement.id, risk_acceptance.id, )))

                else:
                    raise ValueError(f"Error number of accepttors{finding.acceptances_confirmed} \
                                     < number of acceptors required {number_of_acceptors_required}")
    
    return Response(status=status, message=message)

def get_contacts(engagement: Engagement, finding_serverity: str, user):
    rule = settings.RULE_RISK_ACCEPTANCE_ACCORDING_TO_CRITICALITY.get(finding_serverity)
    product_type = engagement.product.get_product_type
    contacts = rule.get("type_contacts")

    get_contacts_dict = {
        "Product Type Manager": product_type.product_type_manager,
        "Product Type Technical Contact": product_type.product_type_technical_contact,
        "Environment Manager": product_type.environment_manager,
        "Environment Technical Contact": product_type.environment_technical_contact
    }
    contact_list = []
    for contact in contacts:
        if contact in get_contacts_dict.keys():
            contact_list.append(get_contacts_dict[contact])
        else:
            raise ValueError(f"Contact {contact} not found")
    # if severity is low load default acceptanced_by = user.id 
    if contact_list == []:
        contact_list.append(user.id)

    return contact_list

def is_permissions_risk_accept(engagement: Engagement, finding_serverity: str, user):
    contacts = get_contacts(engagement, finding_serverity, user)
    contacts_ids = [contact.id for contact in contacts]
    if user.id in contacts_ids:
        # has the permissions
        return True
    return False

def rule_risk_acceptance_according_to_critical(severity, user_rol: str):
    risk_rule = settings.RULE_RISK_ACCEPTANCE_ACCORDING_TO_CRITICALITY.get(severity)
    view_risk_pending = False
    if risk_rule:
        if risk_rule.get("number_acceptors") == 0 and user_rol in risk_rule.get("roles"):
            view_risk_pending = False
        elif risk_rule.get("number_acceptors") != 0 and user_rol not in risk_rule.get("roles"):
            view_risk_pending = True
    return view_risk_pending
