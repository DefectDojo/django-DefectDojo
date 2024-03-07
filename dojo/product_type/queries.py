from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Product_Type, Product_Type_Member, Product_Type_Group, Dojo_User, Role, Global_Role
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission, user_has_permission, \
    role_has_permission
from dojo.group.queries import get_authorized_groups
from dojo.authorization.roles_permissions import Permissions
from django.conf import settings


def get_authorized_product_types(permission):
    user = get_current_user()

    if user is None:
        return Product_Type.objects.none()

    if user.is_superuser:
        return Product_Type.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return Product_Type.objects.all().order_by('name')

    roles = get_roles_for_permission(permission)
    authorized_roles = Product_Type_Member.objects.filter(product_type=OuterRef('pk'),
        user=user,
        role__in=roles)
    authorized_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('pk'),
        group__users=user,
        role__in=roles)
    product_types = Product_Type.objects.annotate(
        member=Exists(authorized_roles),
        authorized_group=Exists(authorized_groups)).order_by('name')
    product_types = product_types.filter(Q(member=True) | Q(authorized_group=True))

    return product_types


def get_authorized_members_for_product_type(product_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        return Product_Type_Member.objects.filter(product_type=product_type).order_by('user__first_name', 'user__last_name').select_related('role', 'product_type', 'user')
    else:
        return None


def get_authorized_groups_for_product_type(product_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        authorized_groups = get_authorized_groups(Permissions.Group_View)
        return Product_Type_Group.objects.filter(product_type=product_type, group__in=authorized_groups).order_by('group__name').select_related('role', 'group')
    else:
        return None


def get_authorized_product_type_members(permission):
    user = get_current_user()

    if user is None:
        return Product_Type_Member.objects.none()

    if user.is_superuser:
        return Product_Type_Member.objects.all().select_related('role')

    if user_has_global_permission(user, permission):
        return Product_Type_Member.objects.all().select_related('role')

    product_types = get_authorized_product_types(permission)
    return Product_Type_Member.objects.filter(product_type__in=product_types).select_related('role')


def query_contacts(*args):
    contacts = list(Product_Type.objects.all().values(*args))
    contacts_dict = {}
    for contact_dict in contacts:
        contacts_dict.update({value: key for key, value in contact_dict.items()})
    return contacts_dict
    

def get_authorized_contacts_for_product_type(severity, product_type):
    contacts_result = []
    user = get_current_user()
    rule = settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(severity)
    contacts_list = rule["type_contacts"]
    product_type_obj = Product_Type.objects.get(id=product_type)

    if hasattr(user, "global_role"):
        if user.global_role.role:
            if user.global_role.role.name in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS:
                contacts_result.append(user.id)

    if contacts_list == [] and rule["number_acceptors"] == 0:
        contacts_result.append(user.id)

    elif not contacts_result:
        for contact_type in contacts_list:
            leader = getattr(product_type_obj, contact_type, None)
            if leader:
                contacts_result.append(leader.id)
            else:
                raise ValueError(f"Leader {contact_type} not found")
    
    if contacts_result:
        contacts_result += query_user_by_rol(settings.ROLE_ALLOWED_TO_ACCEPT_RISKS)
        return Dojo_User.objects.filter(id__in=contacts_result)


def query_user_by_rol(rol):
    # get ids for rol name
    user_list_maintainer = []
    ids_role = list(
        Role.objects.filter(name__in=rol).values_list("id", flat=True))
    if ids_role:
        user_list_maintainer = Global_Role.objects.filter(role_id__in=ids_role).values_list("user_id", flat=True)
    return list(user_list_maintainer)

def get_owner_user():
    user = get_current_user()
    user_owner = Dojo_User.objects.filter(id=user.id)
    return user_owner

def get_authorized_contacts(severity, queryset=None):
    user = get_current_user()
    rule = settings.RULE_RISK_PENDING_ACCORDING_TO_CRITICALITY.get(severity)
    contacts_dict = {}
    contacts_list = []
    contacts = rule["type_contacts"]
    if contacts:
        contacts_dict = query_contacts(*contacts)
        if contacts_dict:
            for key in contacts_dict.keys():
                contacts_list.append(key)
        contacts_list += query_user_by_rol(settings.ROLE_ALLOWED_TO_ACCEPT_RISKS)
    else:
        # in the event that risk does not need acceptance by leaders
        contacts_list.append(user.id)

    # add user current to form acceptance_by field

    if contacts_list:
        return Dojo_User.objects.filter(id__in=contacts_list)

    return Dojo_User.objects.all()


def get_authorized_product_type_members_for_user(user, permission):
    request_user = get_current_user()

    if request_user is None:
        return Product_Type_Member.objects.none()

    if request_user.is_superuser:
        return Product_Type_Member.objects.filter(user=user).select_related('role', 'product_type')

    if hasattr(request_user, 'global_role') and request_user.global_role.role is not None and role_has_permission(request_user.global_role.role.id, permission):
        return Product_Type_Member.objects.filter(user=user).select_related('role', 'product_type')

    product_types = get_authorized_product_types(permission)
    return Product_Type_Member.objects.filter(user=user, product_type__in=product_types).select_related('role', 'product_type')


def get_authorized_product_type_groups(permission):
    user = get_current_user()

    if user is None:
        return Product_Type_Group.objects.none()

    if user.is_superuser:
        return Product_Type_Group.objects.all().select_related('role')

    product_types = get_authorized_product_types(permission)
    return Product_Type_Group.objects.filter(product_type__in=product_types).select_related('role')