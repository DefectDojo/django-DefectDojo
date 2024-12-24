import json
import logging
from dojo.models import Product_Type, Engagement
from django.conf import settings
logger = logging.getLogger(__name__)


def get_contacts_product_typ_and_product(engagement: Engagement, finding_serverity: str, user):
    rule = settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(finding_serverity)
    product_type = engagement.product.get_product_type
    contacts = rule.get("type_contacts").get(json.loads(settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS.split("//")[3])[product_type.name.split(" - ")[0]]).get("users")

    get_contacts_dict = {
        "team_manager": engagement.product.team_manager,
        "product_manager": engagement.product.product_manager,
        "product_manager": engagement.product.technical_contact,
        "product_type_manager": product_type.product_type_manager,
        "product_type_technical_contact": product_type.product_type_technical_contact,
        "environment_manager": product_type.environment_manager,
        "environment_technical_contact": product_type.environment_technical_contact,
    }
    contact_list = []
    for contact in contacts:
        if contact in get_contacts_dict.keys():
            contact_list.append(get_contacts_dict[contact])
        else:
            logger.error(f"Risk_pending: key {contact} not related to a product or product_type")
            raise ValueError(f"Contact {contact} not found")
    if contact_list == []:
        contact_list.append(user)

    return contact_list

