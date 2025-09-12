from crum import get_current_user
from django.db.models import Exists, OuterRef, Q

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import (
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
)


def get_authorized_locations(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Location.objects.none()

    locations = Location.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return locations

    if user_has_global_permission(user, permission):
        return locations

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("product_id"),
        group__users=user,
        role__in=roles)
    locations = locations.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups))
    return locations.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))


def get_authorized_location_finding_reference(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return LocationFindingReference.objects.none()

    location_finding_reference = LocationFindingReference.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return location_finding_reference

    if user_has_global_permission(user, permission):
        return location_finding_reference

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("location__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("location__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("location__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("location__product_id"),
        group__users=user,
        role__in=roles)
    location_finding_reference = location_finding_reference.annotate(
        location__product__prod_type__member=Exists(authorized_product_type_roles),
        location__product__member=Exists(authorized_product_roles),
        location__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        location__product__authorized_group=Exists(authorized_product_groups))
    return location_finding_reference.filter(
        Q(location__product__prod_type__member=True) | Q(location__product__member=True)
        | Q(location__product__prod_type__authorized_group=True) | Q(location__product__authorized_group=True))


def get_authorized_location_product_reference(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return LocationProductReference.objects.none()

    location_product_reference = LocationProductReference.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return location_product_reference

    if user_has_global_permission(user, permission):
        return location_product_reference

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("location__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("location__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("location__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("location__product_id"),
        group__users=user,
        role__in=roles)
    location_product_reference = location_product_reference.annotate(
        location__product__prod_type__member=Exists(authorized_product_type_roles),
        location__product__member=Exists(authorized_product_roles),
        location__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        location__product__authorized_group=Exists(authorized_product_groups))
    return location_product_reference.filter(
        Q(location__product__prod_type__member=True) | Q(location__product__member=True)
        | Q(location__product__prod_type__authorized_group=True) | Q(location__product__authorized_group=True))
