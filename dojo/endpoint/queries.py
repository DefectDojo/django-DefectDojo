from crum import get_current_user
from django.db.models import Q, Subquery

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
)


def get_authorized_endpoints(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint.objects.none()

    endpoints = Endpoint.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return endpoints

    if user_has_global_permission(user, permission):
        return endpoints

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
    return endpoints.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


def get_authorized_endpoint_status(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint_Status.objects.none()

    endpoint_status = Endpoint_Status.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return endpoint_status

    if user_has_global_permission(user, permission):
        return endpoint_status

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
    return endpoint_status.filter(
        Q(endpoint__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(endpoint__product_id__in=Subquery(authorized_product_roles))
        | Q(endpoint__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(endpoint__product_id__in=Subquery(authorized_product_groups)),
    )
