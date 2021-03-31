from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Endpoint, Endpoint_Status, Product_Member, Product_Type_Member
from dojo.authorization.authorization import get_roles_for_permission


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

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
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
        endpoints = endpoints.annotate(
            product__prod_type__member=Exists(authorized_product_type_roles),
            product__member=Exists(authorized_product_roles))
        endpoints = endpoints.filter(
            Q(product__prod_type__member=True) |
            Q(product__member=True))
    else:
        if not user.is_staff:
            endpoints = endpoints.filter(
                Q(product__authorized_users__in=[user]) |
                Q(product__prod_type__authorized_users__in=[user]))
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

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
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
        endpoint_status = endpoint_status.annotate(
            endpoint__product__prod_type__member=Exists(authorized_product_type_roles),
            endpoint__product__member=Exists(authorized_product_roles))
        endpoint_status = endpoint_status.filter(
            Q(endpoint__product__prod_type__member=True) |
            Q(endpoint__product__member=True))
    else:
        if not user.is_staff:
            endpoint_status = endpoint_status.filter(
                Q(endpoint__product__authorized_users__in=[user]) |
                Q(endpoint__product__prod_type__authorized_users__in=[user]))
    return endpoint_status
