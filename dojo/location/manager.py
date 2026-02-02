
from django.db.models import CharField, F, Value
from django.db.models.functions import Coalesce

from dojo.base_models.base import BaseManager, BaseQuerySet


class LocationQueryset(BaseQuerySet):

    """Location Queryset to add chainable queries."""


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
