
from django.db.models import Case, CharField, Count, F, Q, Value, When
from django.db.models.functions import Coalesce

from dojo.base_models.base import BaseManager, BaseQuerySet
from dojo.location.status import FindingLocationStatus, ProductLocationStatus


class LocationQueryset(BaseQuerySet):

    """Location Queryset to add chainable queries."""

    def active_by_products(self):
        return self.prefetch_related("products").filter(products__status=ProductLocationStatus.Active)

    def active_by_product(self, product_id: int):
        return self.prefetch_related("products__product").filter(
            products__status=ProductLocationStatus.Active,
            products__product__id=product_id,
        )

    def active_by_findings(self):
        return self.prefetch_related("findings").filter(findings__status=FindingLocationStatus.Active)

    def active_by_finding(self, finding_id: int):
        return self.prefetch_related("findings__finding").filter(
            findings__status=ProductLocationStatus.Active,
            findings__finding__id=finding_id,
        )

    def total_counts(self):
        return self.prefetch_related("findings", "products").annotate(
            # Products
            total_products=Count("products", distinct=True),
            active_products=Count(
                "products",
                filter=Q(products__status=ProductLocationStatus.Active),
                distinct=True,
            ),
            # Findings
            total_findings=Count("findings", distinct=True),
            active_findings=Count(
                "findings",
                filter=Q(findings__status=FindingLocationStatus.Active),
                distinct=True,
            ),
        )

    def overall_status(self):
        return self.total_counts().annotate(
            # Overall status (active if any product is active)
            overall_status=Case(
                When(
                    Q(active_products__gt=0) | Q(active_findings__gt=0),
                    then=Value(ProductLocationStatus.Active),
                ),
                default=Value(ProductLocationStatus.Mitigated),
                output_field=CharField(),
            ),
        )


class LocationManager(BaseManager):

    """Location manager to manipulate all objects with."""

    QUERY_SET_CLASS = LocationQueryset


class LocationProductReferenceQueryset(BaseQuerySet):

    """LocationProductReference Queryset to add chainable queries."""

    def with_location_annotations(self):
        """
        Annotate char fields from the nullable foreign key `location`.
        Falls back to '' if the relation is NULL.
        """
        return self.annotate(
            location_type=Coalesce(F("location__location_type"), Value("", output_field=CharField())),
            location_value=Coalesce(F("location__location_value"), Value("", output_field=CharField())),
        )


class LocationProductReferenceManager(BaseManager):

    """LocationProductReference manager to manipulate all objects with."""

    QUERY_SET_CLASS = LocationProductReferenceQueryset


class LocationFindingReferenceQueryset(BaseQuerySet):

    """LocationFindingReference Queryset to add chainable queries."""

    def with_location_annotations(self):
        """
        Annotate char fields from the nullable foreign key `location`.
        Falls back to '' if the relation is NULL.
        """
        return self.annotate(
            location_type=Coalesce(F("location__location_type"), Value("", output_field=CharField())),
            location_value=Coalesce(F("location__location_value"), Value("", output_field=CharField())),
        )


class LocationFindingReferenceManager(BaseManager):

    """LocationFindingReference manager to manipulate all objects with."""

    QUERY_SET_CLASS = LocationFindingReferenceQueryset
