import logging
from typing import List
from django.conf import settings
from dataclasses import dataclass
from dojo.models import Engagement 
logger = logging.getLogger(__name__)


def finding_is_black_list():
    pass


def get_abuse_control():
    # se calcula el control de abuso
    pass


def get_number_acceptance_risk(finding):
    # TODO: number acceptaciones 
    return 1


def get_contacts(engagement: Engagement, finding_serverity: str, user_id: int):
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
        contact_list.append(user_id)

    return contact_list


def rule_risk_acceptance_according_to_critical(severity, user_rol: str):
    risk_rule = settings.RULE_RISK_ACCEPTANCE_ACCORDING_TO_CRITICALITY.get(severity)
    view_risk_pending = False
    if risk_rule:
        if risk_rule.get("number_acceptors") == 0 and user_rol in risk_rule.get("roles"):
            view_risk_pending = False
        elif risk_rule.get("number_acceptors") != 0 and user_rol not in risk_rule.get("roles"):
            view_risk_pending = True
    return view_risk_pending
