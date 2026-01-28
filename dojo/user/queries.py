from crum import get_current_user
from django.db.models import Q, Subquery

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


def get_authorized_users_for_product_type(users, product_type, permission):
    roles = get_roles_for_permission(permission)

    # Get user IDs via subqueries instead of materializing into Python lists
    product_type_member_users = Product_Type_Member.objects.filter(
        product_type=product_type, role__in=roles,
    ).values("user_id")

    # Get group IDs that have access to this product type
    product_type_group_ids = Product_Type_Group.objects.filter(
        product_type=product_type, role__in=roles,
    ).values("group_id")

    global_role_group_ids = Global_Role.objects.filter(
        role__in=roles, group__isnull=False,
    ).values("group_id")

    # Get users from those groups
    group_member_users = Dojo_Group_Member.objects.filter(
        Q(group_id__in=Subquery(product_type_group_ids))
        | Q(group_id__in=Subquery(global_role_group_ids)),
    ).values("user_id")

    return users.filter(
        Q(id__in=Subquery(product_type_member_users))
        | Q(id__in=Subquery(group_member_users))
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True),
    )


def get_authorized_users_for_product_and_product_type(users, product, permission):
    if users is None:
        users = Dojo_User.objects.filter(is_active=True)

    roles = get_roles_for_permission(permission)

    # Get user IDs via subqueries instead of materializing into Python lists
    product_member_users = Product_Member.objects.filter(
        product=product, role__in=roles,
    ).values("user_id")

    product_type_member_users = Product_Type_Member.objects.filter(
        product_type=product.prod_type, role__in=roles,
    ).values("user_id")

    # Get group IDs that have access to this product or product type
    product_group_ids = Product_Group.objects.filter(
        product=product, role__in=roles,
    ).values("group_id")

    product_type_group_ids = Product_Type_Group.objects.filter(
        product_type=product.prod_type, role__in=roles,
    ).values("group_id")

    global_role_group_ids = Global_Role.objects.filter(
        role__in=roles, group__isnull=False,
    ).values("group_id")

    # Get users from those groups
    group_member_users = Dojo_Group_Member.objects.filter(
        Q(group_id__in=Subquery(product_group_ids))
        | Q(group_id__in=Subquery(product_type_group_ids))
        | Q(group_id__in=Subquery(global_role_group_ids)),
    ).values("user_id")

    return users.filter(
        Q(id__in=Subquery(product_member_users))
        | Q(id__in=Subquery(product_type_member_users))
        | Q(id__in=Subquery(group_member_users))
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True),
    )


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

    # Get user IDs via subqueries instead of materializing into Python lists
    product_member_users = Product_Member.objects.filter(
        product_id__in=Subquery(authorized_products), role__in=roles,
    ).values("user_id")

    product_type_member_users = Product_Type_Member.objects.filter(
        product_type_id__in=Subquery(authorized_product_types), role__in=roles,
    ).values("user_id")

    # Get group IDs that have access to authorized products/product types
    product_group_ids = Product_Group.objects.filter(
        product_id__in=Subquery(authorized_products), role__in=roles,
    ).values("group_id")

    product_type_group_ids = Product_Type_Group.objects.filter(
        product_type_id__in=Subquery(authorized_product_types), role__in=roles,
    ).values("group_id")

    # Get users from those groups
    group_member_users = Dojo_Group_Member.objects.filter(
        Q(group_id__in=Subquery(product_group_ids))
        | Q(group_id__in=Subquery(product_type_group_ids)),
    ).values("user_id")

    return users.filter(
        Q(id__in=Subquery(product_member_users))
        | Q(id__in=Subquery(product_type_member_users))
        | Q(id__in=Subquery(group_member_users))
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True),
    )
