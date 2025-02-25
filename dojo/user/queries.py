import logging
from crum import get_current_user
from django.db.models import Q
from django.conf import settings

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import (
    Dojo_Group_Member,
    Dojo_User,
    Global_Role,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.request_cache import cache_for_request

logger = logging.getLogger(__name__)


def get_authorized_users_for_product_type(users, product_type, permission):
    roles = get_roles_for_permission(permission)
    product_type_members = Product_Type_Member.objects \
        .filter(product_type=product_type, role__in=roles) \
        .select_related("user")
    product_type_groups = Product_Type_Group.objects \
        .filter(product_type=product_type, role__in=roles)
    global_roles = Global_Role.objects.filter(role__in=roles)
    group_members = Dojo_Group_Member.objects \
        .filter(Q(group__in=[ptg.group for ptg in product_type_groups])
                | Q(group__in=[gr.group for gr in global_roles])) \
        .select_related("user")

    return users.filter(Q(id__in=[ptm.user.id for ptm in product_type_members])
        | Q(id__in=[gm.user.id for gm in group_members])
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True))


def get_authorized_users_for_product_and_product_type(users, product, permission):
    if users is None:
        users = Dojo_User.objects.filter(is_active=True)

    roles = get_roles_for_permission(permission)

    product_members = Product_Member.objects \
        .filter(product=product, role__in=roles) \
        .select_related("user")
    product_type_members = Product_Type_Member.objects \
        .filter(product_type=product.prod_type, role__in=roles) \
        .select_related("user")
    product_groups = Product_Group.objects \
        .filter(product=product, role__in=roles)
    product_type_groups = Product_Type_Group.objects \
        .filter(product_type=product.prod_type, role__in=roles)
    global_roles = Global_Role.objects.filter(role__in=roles)
    group_members = Dojo_Group_Member.objects \
        .filter(
            Q(group__in=[pg.group for pg in product_groups])
            | Q(group__in=[ptg.group for ptg in product_type_groups])
            | Q(group__in=[gr.group for gr in global_roles])) \
        .select_related("user")

    return users.filter(Q(id__in=[pm.user.id for pm in product_members])
        | Q(id__in=[ptm.user.id for ptm in product_type_members])
        | Q(id__in=[gm.user.id for gm in group_members])
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True))


# Cached because it is a complex SQL query and it is called 3 times for the engagement lists in products
@cache_for_request
def get_authorized_users(permission, user=None):
    if user is None:
        user = get_current_user()

    if user is None:
        return Dojo_User.objects.none()

    if user.is_anonymous:
        return Dojo_User.objects.none()

    users = Dojo_User.objects.all().order_by("first_name", "last_name", "username")

    if user.is_superuser or user_has_global_permission(user, permission):
        return users

    authorized_products = get_authorized_products(permission).values("id")
    authorized_product_types = get_authorized_product_types(permission).values("id")

    roles = get_roles_for_permission(permission)
    product_members = Product_Member.objects \
        .filter(product_id__in=authorized_products, role__in=roles) \
        .select_related("user")
    product_type_members = Product_Type_Member.objects \
        .filter(product_type_id__in=authorized_product_types, role__in=roles) \
        .select_related("user")
    product_groups = Product_Group.objects \
        .filter(product_id__in=authorized_products, role__in=roles)
    product_type_groups = Product_Type_Group.objects \
        .filter(product_type_id__in=authorized_product_types, role__in=roles)
    group_members = Dojo_Group_Member.objects \
        .filter(
            Q(group__in=[pg.group for pg in product_groups])
            | Q(group__in=[ptg.group for ptg in product_type_groups])) \
        .select_related("user")
    return users.filter(Q(id__in=[pm.user.id for pm in product_members])
        | Q(id__in=[ptm.user.id for ptm in product_type_members])
        | Q(id__in=[gm.user.id for gm in group_members])
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True))


def get_all_user_by_role(role=None, user=None):
    if user is None:
        return Dojo_User.objects.none()

    if user.is_superuser:
        return Dojo_User.objects.all()

    if hasattr(user, "global_role"):
        if user.global_role.role:
            if user.global_role.role.name in settings.ROLE_ALLOWED_TO_ACCEPT_RISKS:
                return Dojo_User.objects.all()

    queryset_combined = Product_Type_Member.objects.select_related('role').filter(role__name=role).values(
        'user_id',
        'role__name',
        'role_id').union(
            Product_Member.objects.select_related('role').filter(role__name=role).values(
                'user_id',
                'role__name',
                'role_id'))
    user_ids = queryset_combined.values_list('user_id', flat=True) 
    user_query = Dojo_User.objects.filter(id__in=list(user_ids))

    return user_query


def get_user(user_name):
    try:
        return Dojo_User.objects.get(username=user_name)
    except Dojo_User.DoesNotExist:
        logger.error('User %s does not exist', user_name)

def get_users_authorized_role_permission(product, permission, role):
    roles = get_roles_for_permission(permission)
    if role not in roles:
        return Dojo_User.objects.none()
    
    product_type_members = Product_Type_Member.objects \
        .filter(product_type=product.prod_type, role__in=[role]) \
        .select_related("user")

    return Dojo_User.objects.filter(Q(id__in=[ptm.user.id for ptm in product_type_members])).order_by("first_name", "last_name", "username")

