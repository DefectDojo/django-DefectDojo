
from django.db.models import CharField, F, Value
from django.db.models.functions import Coalesce

from dojo.base_models.base import BaseManager, BaseQuerySet
from dojo.location.status import rollup_finding_location_status


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

    def rolled_up_statuses(self) -> dict[tuple[int, int], str]:
        """
        Return the status of each (finding id, location id) pair in this queryset, rolled up across tests.

        One location on one finding can hold a row per test that reported it; see
        ``rollup_finding_location_status`` for how their statuses combine.
        """
        statuses: dict[tuple[int, int], set[str]] = {}
        for finding_id, location_id, status in self.values_list("finding_id", "location_id", "status"):
            statuses.setdefault((finding_id, location_id), set()).add(status)
        return {key: rollup_finding_location_status(values) for key, values in statuses.items()}


class LocationFindingReferenceManager(BaseManager):

    """LocationFindingReference manager to manipulate all objects with."""

    QUERY_SET_CLASS = LocationFindingReferenceQueryset
