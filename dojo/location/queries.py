import logging

from django.db.models import (
    Case,
    CharField,
    Count,
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

try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import (
    Finding,
)
from dojo.query_utils import build_count_subquery

logger = logging.getLogger(__name__)


def get_authorized_locations(permission, queryset=None, user=None):
    impl = get_auth_filter("location.get_authorized_locations")
    if impl:
        return impl(permission, queryset=queryset, user=user)
    return Location.objects.all().order_by("id") if queryset is None else queryset


def get_authorized_location_finding_reference(permission, queryset=None, user=None):
    impl = get_auth_filter("location.get_authorized_location_finding_reference")
    if impl:
        return impl(permission, queryset=queryset, user=user)
    return LocationFindingReference.objects.all().order_by("id") if queryset is None else queryset


def get_authorized_location_product_reference(permission, queryset=None, user=None):
    impl = get_auth_filter("location.get_authorized_location_product_reference")
    if impl:
        return impl(permission, queryset=queryset, user=user)
    return LocationProductReference.objects.all().order_by("id") if queryset is None else queryset


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
