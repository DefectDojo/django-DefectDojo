import logging

from crum import get_current_user
from django.db.models import (
    Case,
    CharField,
    Count,
    Exists,
    F,
    IntegerField,
    OuterRef,
    Q,
    QuerySet,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Coalesce

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import (
    Finding,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
)
from dojo.query_utils import build_count_subquery

logger = logging.getLogger(__name__)


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
        product_type=OuterRef("products__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("products__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("products__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("products__product_id"),
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
        product_type=OuterRef("location__products__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("location__products__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("location__products__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("location__products__product_id"),
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
    location_product_reference = location_product_reference.annotate(
        location__product__prod_type__member=Exists(authorized_product_type_roles),
        location__product__member=Exists(authorized_product_roles),
        location__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        location__product__authorized_group=Exists(authorized_product_groups))
    return location_product_reference.filter(
        Q(location__product__prod_type__member=True) | Q(location__product__member=True)
        | Q(location__product__prod_type__authorized_group=True) | Q(location__product__authorized_group=True))


def annotate_location_counts_and_status(locations):
    # Annotate the queryset with counts of findings
    # This aggregates the total and active findings by joining LocationFindingReference.
    finding_counts = (
        LocationFindingReference.objects.prefetch_related("location")
        .filter(location=OuterRef("id"))
        .values("location")
        .annotate(
            total_findings=Count("finding_id", distinct=True),
            active_findings=Count(
                "finding_id",
                filter=Q(status=FindingLocationStatus.Active),
                distinct=True,
            ),
        )
        .order_by("location")
    )
    # Annotate the queryset with counts of products
    # This aggregates the total and active products by joining LocationProductReference.
    product_counts = (
        LocationProductReference.objects.prefetch_related("location")
        .filter(location=OuterRef("id"))
        .values("location")
        .annotate(
            total_products=Count("product_id", distinct=True),
            active_products=Count(
                "product_id",
                filter=Q(status=ProductLocationStatus.Active),
                distinct=True,
            ),
        )
        .order_by("location")
    )
    # Annotate each Location with findings counts, products counts, and overall status.
    return locations.prefetch_related("url").annotate(
        total_findings=Coalesce(Subquery(finding_counts.values("total_findings")[:1]), Value(0), output_field=IntegerField()),
        active_findings=Coalesce(Subquery(finding_counts.values("active_findings")[:1]), Value(0), output_field=IntegerField()),
        total_products=Coalesce(Subquery(product_counts.values("total_products")[:1]), Value(0), output_field=IntegerField()),
        active_products=Coalesce(Subquery(product_counts.values("active_products")[:1]), Value(0), output_field=IntegerField()),
        mitigated_findings=F("total_findings") - F("active_findings"),
        overall_status=Case(
            When(
                Q(active_products__gt=0) | Q(active_findings__gt=0),
                then=Value(ProductLocationStatus.Active),
            ),
            default=Value(ProductLocationStatus.Mitigated),
            output_field=CharField(),
        ),
    )


def prefetch_for_locations(locations):
    if isinstance(locations, QuerySet):
        locations = locations.prefetch_related("tags")
        active_finding_subquery = build_count_subquery(
            Finding.objects.filter(locations=OuterRef("pk"), active=True),
            group_field="locations",
        )
        locations = locations.annotate(active_finding_count=Coalesce(active_finding_subquery, Value(0)))
    else:
        logger.debug("unable to prefetch because query was already executed")

    return locations
