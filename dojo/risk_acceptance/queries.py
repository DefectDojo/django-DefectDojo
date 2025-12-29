from crum import get_current_user
from django.db.models import Q, Subquery

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import Product_Group, Product_Member, Product_Type_Group, Product_Type_Member, Risk_Acceptance
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_risk_acceptances(permission):
    user = get_current_user()

    if user is None:
        return Risk_Acceptance.objects.none()

    if user.is_superuser:
        return Risk_Acceptance.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Risk_Acceptance.objects.all().order_by("id")

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
    return Risk_Acceptance.objects.filter(
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")
