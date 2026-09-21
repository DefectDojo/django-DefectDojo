import logging

from django.db import transaction
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

try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.authorization.roles_permissions import Permissions
from dojo.finding.queries import get_authorized_findings
from dojo.location.feature import locations_enabled
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.product.queries import get_authorized_products
from dojo.query_utils import build_count_subquery

logger = logging.getLogger(__name__)


def location_prefetch_lookups(prefix: str = "") -> list[str]:
    """
    Prefetch lookups for the location relation that the hash and deduplication paths read
    through ``Finding.get_locations()``, for the location model actually in use.

    Endpoint rows are not deleted by the move to Locations, and ``Endpoint.__init__`` raises
    ``NotImplementedError`` once ``V3_FEATURE_LOCATIONS`` is on (see
    ``Endpoint.allow_endpoint_init``). So prefetching the endpoint relation under V3 hydrates
    the deprecated model for every surviving row and kills the caller -- on a migrated
    instance, not on a fresh one, which is why it is easy to miss. Under V3 ``get_locations()``
    reads URL locations and never touches endpoints, so the endpoint prefetch is dead weight
    there in any case.

    :param prefix: relation path to the Finding, e.g. ``"finding__"`` when paging a model that
        reaches the finding through a relation.
    """
    if locations_enabled():
        return [f"{prefix}locations__location__url"]
    # TODO: Delete this after the move to Locations
    return [f"{prefix}endpoints"]


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


def authorized_finding_references(user=None):
    """
    Finding references the user may see, as a base for per-Location counts.

    A Location is deduplicated across every product that references it, so counting
    all of its references reports on products the user is not authorized for.
    """
    return LocationFindingReference.objects.filter(
        finding__in=get_authorized_findings(Permissions.Finding_View, user=user),
    )


def authorized_product_references(user=None):
    """Product references the user may see, as a base for per-Location counts."""
    return LocationProductReference.objects.filter(
        product__in=get_authorized_products(Permissions.Product_View, user),
    )


def remove_location_references(locations, products):
    """
    Drop ``products``' references to ``locations``, then delete any Location left
    with none.

    A Location is deduplicated across every product that records the same value, so
    deleting the row itself removes it from products the caller has no rights over.
    The reference is the per-product object, so it is what a delete acts on.
    """
    location_ids = list(locations.values_list("id", flat=True))
    if not location_ids:
        return 0
    with transaction.atomic():
        LocationFindingReference.objects.filter(
            location_id__in=location_ids,
            finding__test__engagement__product__in=products,
        ).delete()
        removed = LocationProductReference.objects.filter(
            location_id__in=location_ids,
            product__in=products,
        ).delete()[0]
        Location.objects.filter(
            id__in=location_ids,
            products__isnull=True,
            findings__isnull=True,
        ).delete()
    return removed


def locations_shared_outside(locations, products):
    """Locations in ``locations`` that something outside ``products`` also references."""
    foreign_products = LocationProductReference.objects.filter(
        location=OuterRef("pk"),
    ).exclude(product__in=products)
    foreign_findings = LocationFindingReference.objects.filter(
        location=OuterRef("pk"),
    ).exclude(finding__test__engagement__product__in=products)
    return locations.filter(Exists(foreign_products) | Exists(foreign_findings))


def readable_tag_locations(user=None):
    """
    Locations whose tag set is entirely the caller's to read.

    A Location row is deduplicated globally and its tag set is one field shared by every
    product referencing it, with no record of which product contributed which tag. So the
    set is only the caller's to read when they are authorized for every product on the row.
    """
    products = get_authorized_products(Permissions.Product_View, user=user)
    return Location.objects.exclude(
        Exists(
            LocationProductReference.objects.filter(
                location=OuterRef("pk"),
            ).exclude(product__in=products),
        )
        | Exists(
            LocationFindingReference.objects.filter(
                location=OuterRef("pk"),
            ).exclude(finding__test__engagement__product__in=products),
        ),
    )


def location_tags_readable(location, user=None):
    """Whether the caller may read the shared tag set on ``location``."""
    return readable_tag_locations(user).filter(pk=location.pk).exists()


def readable_tag_match(location_field, user=None, **lookups):
    """
    ``Exists`` over readable tag sets, for filtering without joining the tag relation.

    Use this rather than a joined ``filter()``: the host view runs ``distinct("url__host")``,
    which a bare ``.distinct()`` added to deduplicate a join would clear.
    """
    return Exists(
        readable_tag_locations(user).filter(pk=OuterRef(location_field), **lookups),
    )


def annotate_location_counts_and_status(locations, user=None):
    # Annotate the queryset with counts of findings
    # This aggregates the total and active findings by joining LocationFindingReference.
    finding_counts = (
        authorized_finding_references(user)
        .prefetch_related("location")
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
        authorized_product_references(user)
        .prefetch_related("location")
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


def prefetch_for_locations(locations, user=None):
    if isinstance(locations, QuerySet):
        locations = locations.prefetch_related("tags")
        # Finding.locations is the reverse accessor for LocationFindingReference, so
        # the count has to go through the reference rather than compare its id to a
        # Location id.
        active_finding_subquery = build_count_subquery(
            authorized_finding_references(user).filter(
                location=OuterRef("pk"),
                status=FindingLocationStatus.Active,
            ),
            group_field="location",
        )
        locations = locations.annotate(active_finding_count=Coalesce(active_finding_subquery, Value(0)))
    else:
        logger.debug("unable to prefetch because query was already executed")

    return locations
