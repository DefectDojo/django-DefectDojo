from dojo.models import (
    Product_Type,
    Product_Type_Member,
    Role,
    Risk_Acceptance,
    Dojo_User,
)
from django.db.models import Q
import ast


def add_technical_contact_whit_member(product_type: Product_Type, pt_form):
    technical_contacts = product_type.get_contacts()
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
