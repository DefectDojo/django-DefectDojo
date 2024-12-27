from dojo.api_v2.api_error import ApiError
from dojo.models import (
    Product_Type,
    Product_Type_Member,
    Role,
    Risk_Acceptance,
    Dojo_User,
    Product,
)
from django.db.models import Q
import ast


def get_contacts(product_type: Product_Type = None, product: Product = None):
    conctacts = {"product_type": {}, "product": {}}
    if product_type is not None and isinstance(product_type, Product_Type):
        conctacts["product_type"] = get_contacts_product_type(product_type)
    if product is not None and isinstance(product, Product):
        conctacts["product"] = get_contacts_product(product)
    else:
        raise ApiError.precondition_failed(
            detail="Object is not object product_type o product have contacts"
            )
    return conctacts


def get_contacts_product(product: Product):
    contacts = {
        "product_manager": None,
        "technical_contact": None,
        "team_manager": None,
    }
    contacts["product_manager"] = (
        product.product_manager
        )
    contacts["technical_contact"] = (
        product.technical_contact
        )

    contacts["team_manager"] = product.team_manager

    return contacts


def get_contacts_product_type(product_type: Product_Type):
    contacts = {
        "product_type_manager": None,
        "product_type_technical_contact": None,
        "environment_manager": None,
        "environment_technical_contact": None,
    }
    contacts["product_type_manager"] = product_type.product_type_manager
    contacts["product_type_technical_contact"] = (
        product_type.product_type_technical_contact
    )
    contacts["environment_manager"] = product_type.environment_manager
    contacts["environment_technical_contact"] = (
        product_type.environment_technical_contact
    )

    return contacts


def add_technical_contact_whit_member(product_type: Product_Type, pt_form):
    technical_contacts = get_contacts_product_type(product_type)
    for name_contact in technical_contacts:
        technical_contact = technical_contacts.get(name_contact, None)
        if technical_contact:
            members = Product_Type_Member.objects.filter(
                product_type=product_type, user=technical_contact
            )
            if members.count() == 0:
                product_type_member = Product_Type_Member()
                product_type_member.product_type = product_type
                product_type_member.user = technical_contact
                product_type_member.role = Role.objects.get(name="Leader")
                product_type_member.save()
            if name_contact in pt_form.changed_data:
                user_original = (
                    Dojo_User.objects.get(id=pt_form.initial[name_contact])
                    if pt_form.initial[name_contact]
                    else None
                )
                risk_acceptances = (
                    Risk_Acceptance.objects.filter(
                        Q(accepted_by__contains=user_original.username)
                        & Q(accepted_findings__risk_status="Risk Pending")
                    )
                    if user_original
                    else []
                )
                for risk in risk_acceptances:
                    current_accepted_by = ast.literal_eval(risk.accepted_by)
                    updated_accepted_by = list(
                        map(
                            lambda x: x.replace(
                                user_original.username, technical_contact.username
                            ),
                            current_accepted_by,
                        )
                    )
                    risk.accepted_by = str(updated_accepted_by)
                    risk.save()
