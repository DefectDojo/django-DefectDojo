

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

from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus


def annotate_host_contents(queryset: QuerySet[Location]) -> QuerySet[Location]:
    # Annotate the queryset with counts of findings per host.
    # This aggregates the total and active findings for each host by joining LocationFindingReference.
    finding_host_counts = (
        LocationFindingReference.objects.prefetch_related("location__url")
        .filter(location__url__host=OuterRef("url__host"))
        .values("location__url__host")
        .annotate(
            total_findings=Count("finding_id", distinct=True),
            active_findings=Count(
                "finding_id",
                filter=Q(status=FindingLocationStatus.Active),
                distinct=True,
            ),
        )
        .order_by("location__url__host")
    )
    # Annotate the queryset with counts of products per host.
    # This aggregates the total and active products for each host by joining LocationProductReference.
    product_host_counts = (
        LocationProductReference.objects.prefetch_related("location__url")
        .filter(location__url__host=OuterRef("url__host"))
        .values("location__url__host")
        .annotate(
            total_products=Count("product_id", distinct=True),
            active_products=Count(
                "product_id",
                filter=Q(status=ProductLocationStatus.Active),
                distinct=True,
            ),
        )
        .order_by("location__url__host")
    )
    # Annotate each Location with host, findings, products, and overall status.
    return queryset.prefetch_related("url").annotate(
        host=Coalesce(F("url__host"), Value("", output_field=CharField())),
        total_findings=Coalesce(Subquery(finding_host_counts.values("total_findings")[:1]), Value(0), output_field=IntegerField()),
        active_findings=Coalesce(Subquery(finding_host_counts.values("active_findings")[:1]), Value(0), output_field=IntegerField()),
        total_products=Coalesce(Subquery(product_host_counts.values("total_products")[:1]), Value(0), output_field=IntegerField()),
        active_products=Coalesce(Subquery(product_host_counts.values("active_products")[:1]), Value(0), output_field=IntegerField()),
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
