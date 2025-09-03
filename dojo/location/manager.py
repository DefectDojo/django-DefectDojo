from typing import Self

from django.db.models import Case, CharField, Count, F, Q, Value, When
from django.db.models.functions import Coalesce

from dojo.base_models.base import BaseManager, BaseQuerySet
from dojo.location.status import FindingLocationStatus, ProductLocationStatus


class LocationQueryset(BaseQuerySet):

    """Location Queryset to add chainable queries."""

    def vulnerable_by_products(self):
        return self.filter(product_locations__status=ProductLocationStatus.Active)

    def vulnerable_by_product(self, product_id: int):
        return self.filter(
            product_locations__status=ProductLocationStatus.Active,
            product_locations__product__id=product_id,
        )

    def vulnerable_by_findings(self):
        return self.filter(finding_locations__status=FindingLocationStatus.Active)

    def vulnerable_by_finding(self, finding_id: int):
        return self.filter(
            finding_locations__status=ProductLocationStatus.Active,
            finding_locations__finding__id=finding_id,
        )

    def status_and_total_counts(self):
        return self.annotate(
            # Products
            total_products=Count("product_locations", distinct=True),
            vulnerable_products=Count(
                "product_locations",
                filter=Q(product_locations__status=ProductLocationStatus.Active),
                distinct=True,
            ),
            # Findings
            total_findings=Count("finding_locations", distinct=True),
            vulnerable_findings=Count(
                "finding_locations",
                filter=Q(finding_locations__status=FindingLocationStatus.Active),
                distinct=True,
            ),
        )

    def overall_status(self):
        return self.status_and_total_counts().annotate(
            # Overall status (active if any product is active)
            overall_status=Case(
                When(
                    Q(vulnerable_products__gt=0) | Q(vulnerable_findings__gt=0),
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

    def get_queryset(self) -> Self:
        return super().get_queryset().with_location_annotations()


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

    def get_queryset(self) -> Self:
        return super().get_queryset().with_location_annotations()
