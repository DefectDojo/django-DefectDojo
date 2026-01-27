from crum import get_current_user
from django.db.models import Q, Subquery

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import Cred_Mapping, Product_Group, Product_Member, Product_Type_Group, Product_Type_Member
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_cred_mappings(permission):
    """Cached - returns all cred mappings the user is authorized to see."""
    user = get_current_user()

    if user is None:
        return Cred_Mapping.objects.none()

    cred_mappings = Cred_Mapping.objects.all().order_by("id")

    if user.is_superuser:
        return cred_mappings

    if user_has_global_permission(user, permission):
        return cred_mappings

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
    return cred_mappings.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


def get_authorized_cred_mappings_for_queryset(permission, queryset):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    user = get_current_user()

    if user is None:
        return Cred_Mapping.objects.none()

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
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )
