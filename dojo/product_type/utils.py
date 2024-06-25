from dojo.models import Product_Type, Product_Type_Member, Role

def get_technical_contacts(product_type: Product_Type):
    technical_contacts = []
    technical_contacts.append(product_type.product_type_manager)
    technical_contacts.append(product_type.product_type_technical_contact)
    technical_contacts.append(product_type.environment_manager)
    technical_contacts.append(product_type.environment_technical_contact)

    return technical_contacts

def add_technical_contact_whit_member(product_type: Product_Type):
    technical_contacts = get_technical_contacts(product_type)
    for technical_contact in technical_contacts:
        if technical_contact:
            members = Product_Type_Member.objects.filter(product_type=product_type, user=technical_contact)
            if members.count() == 0:
                product_type_member = Product_Type_Member()
                product_type_member.product_type = product_type
                product_type_member.user = technical_contact
                product_type_member.role = Role.objects.get(name="Leader") 
                product_type_member.save()

