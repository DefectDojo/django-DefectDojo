from crum import get_current_user
from django.db.models import Q, Subquery

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import Finding_Group, Product_Group, Product_Member, Product_Type_Group, Product_Type_Member
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_finding_groups(permission, user=None):
    """Cached - returns all finding groups the user is authorized to see."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Finding_Group.objects.none()

    finding_groups = Finding_Group.objects.all()

    if user.is_superuser:
        return finding_groups

    if user_has_global_permission(user, permission):
        return finding_groups

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return finding_groups.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


def get_authorized_finding_groups_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Finding_Group.objects.none()

    if user.is_superuser:
        return queryset

    if user_has_global_permission(user, permission):
        return queryset

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return queryset.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )
