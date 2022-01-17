from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Endpoint, Endpoint_Status, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_endpoints(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint.objects.none()

    if queryset is None:
        endpoints = Endpoint.objects.all()
    else:
        endpoints = queryset

    if user.is_superuser:
        return endpoints

    if user_has_global_permission(user, permission):
        return endpoints

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('product__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('product_id'),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('product_id'),
        group__users=user,
        role__in=roles)
    endpoints = endpoints.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups))
    endpoints = endpoints.filter(
        Q(product__prod_type__member=True) | Q(product__member=True) |
        Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))

    return endpoints


def get_authorized_endpoint_status(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint_Status.objects.none()

    if queryset is None:
        endpoint_status = Endpoint_Status.objects.all()
    else:
        endpoint_status = queryset

    if user.is_superuser:
        return endpoint_status

    if user_has_global_permission(user, permission):
        return endpoint_status

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('endpoint__product__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('endpoint__product_id'),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('endpoint__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('endpoint__product_id'),
        group__users=user,
        role__in=roles)
    endpoint_status = endpoint_status.annotate(
        endpoint__product__prod_type__member=Exists(authorized_product_type_roles),
        endpoint__product__member=Exists(authorized_product_roles),
        endpoint__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        endpoint__product__authorized_group=Exists(authorized_product_groups))
    endpoint_status = endpoint_status.filter(
        Q(endpoint__product__prod_type__member=True) | Q(endpoint__product__member=True) |
        Q(endpoint__product__prod_type__authorized_group=True) | Q(endpoint__product__authorized_group=True))

    return endpoint_status
