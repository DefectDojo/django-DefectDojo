import logging
from typing import TypeVar

from django.core.exceptions import ValidationError
from django.db.models import QuerySet
from django.utils import timezone

from dojo.celery import app
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.location.models import AbstractLocation, LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    Dojo_User,
    Finding,
)
from dojo.tools.locations import LocationData
from dojo.url.models import URL

logger = logging.getLogger(__name__)


# TypeVar to represent unsaved locations coming from parsers. These might be existing AbstractLocations (when linking
# existing endpoints) or LocationData objects sent by the parser.
UnsavedLocation = TypeVar("UnsavedLocation", LocationData, AbstractLocation)


# test_notifications.py: Implement Locations
class LocationManager:
    @classmethod
    def get_or_create_location(cls, unsaved_location: AbstractLocation) -> AbstractLocation | None:
        """Gets/creates the given AbstractLocation."""
        if isinstance(unsaved_location, URL):
            return URL.get_or_create_from_object(unsaved_location)
        logger.debug(f"IMPORT_SCAN: Unsupported location type: {type(unsaved_location)}")
        return None

    @classmethod
    def make_abstract_locations(cls, locations: list[UnsavedLocation]) -> list[AbstractLocation]:
        """Converts the list of unsaved locations (AbstractLocation/LocationData objects) to a list of AbstractLocations."""
        abstract_locations = []

        for location in locations:
            if isinstance(location, AbstractLocation):
                abstract_locations.append(location)
            elif isinstance(location, LocationData) and location.type == URL.get_location_type():
                try:
                    abstract_locations.append(URL.from_location_data(location))
                except (ValidationError, ValueError):
                    logger.debug("Skipping invalid location data: %s", location)
            else:
                logger.debug(f"Could not create AbstractLocation from type: {type(location)}")

        return abstract_locations

    @classmethod
    @app.task
    def add_locations_to_unsaved_finding(
        cls,
        finding: Finding,
        locations: list[UnsavedLocation],
        **kwargs: dict,  # noqa: ARG003
    ) -> None:
        """Creates AbstractLocation objects from the given list and links them to the given finding."""
        locations = cls.clean_unsaved_locations(locations)

        logger.debug(f"IMPORT_SCAN: Adding {len(locations)} locations to finding: {finding}")

        # LOCATION LOCATION LOCATION
        # TODO: bulk create the finding/product refs...
        locations_saved = 0
        for unsaved_location in locations:
            if saved_location := cls.get_or_create_location(unsaved_location):
                locations_saved += 1
                association_data = unsaved_location.get_association_data()
                saved_location.location.associate_with_finding(
                    finding,
                    status=FindingLocationStatus.Active,
                    relationship=association_data.relationship_type,
                    relationship_data=association_data.relationship_data,
                )

        logger.debug(f"IMPORT_SCAN: {locations_saved} locations imported")

    @app.task
    def mitigate_location_status(
        location_refs: QuerySet[LocationFindingReference],  # noqa: N805
        user: Dojo_User,
        **kwargs: dict,
    ) -> None:
        """Mitigate all given (non-mitigated) location refs"""
        location_refs.exclude(status=FindingLocationStatus.Mitigated).update(
            auditor=user,
            audit_time=timezone.now(),
            status=FindingLocationStatus.Mitigated,
        )

    @app.task
    def reactivate_location_status(
        location_refs: QuerySet[LocationFindingReference],  # noqa: N805
        **kwargs: dict,
    ) -> None:
        """Reactivate all given (mitigated) locations refs"""
        location_refs.filter(status=FindingLocationStatus.Mitigated).update(
            auditor=None,
            audit_time=timezone.now(),
            status=FindingLocationStatus.Active,
        )

    def chunk_locations_and_disperse(
        self,
        finding: Finding,
        locations: list[UnsavedLocation],
        **kwargs: dict,
    ) -> None:
        if not locations:
            return
        dojo_dispatch_task(self.add_locations_to_unsaved_finding, self, finding, locations, sync=True)

    @classmethod
    def clean_unsaved_locations(
        cls,
        locations: list[UnsavedLocation],
    ) -> list[AbstractLocation]:
        """
        Convert locations represented as LocationData dataclasses to the appropriate AbstractLocation type, then clean
        them. For any endpoints that fail this validation process, log a message that broken locations are being stored.
        """
        locations = list(set(cls.make_abstract_locations(locations)))
        for location in locations:
            try:
                location.clean()
            except ValidationError as e:
                logger.warning("DefectDojo is storing broken locations because cleaning wasn't successful: %s", e)
        return locations

    def chunk_locations_and_reactivate(
        self,
        location_refs: QuerySet[LocationFindingReference],
        **kwargs: dict,
    ) -> None:
        dojo_dispatch_task(LocationManager.reactivate_location_status, location_refs, sync=True)

    def chunk_locations_and_mitigate(
        self,
        location_refs: QuerySet[LocationFindingReference],
        user: Dojo_User,
        **kwargs: dict,
    ) -> None:
        dojo_dispatch_task(LocationManager.mitigate_location_status, location_refs, user, sync=True)

    def update_location_status(
        self,
        existing_finding: Finding,
        new_finding: Finding,
        user: Dojo_User,
        **kwargs: dict,
    ) -> None:
        """Update the list of locations from the new finding with the list that is in the old finding"""
        # New endpoints are already added in serializers.py / views.py (see comment "# for existing findings: make sure endpoints are present or created")
        # So we only need to mitigate endpoints that are no longer present
        # using `.all()` will mark as mitigated also `endpoint_status` with flags `false_positive`, `out_of_scope` and `risk_accepted`. This is a known issue. This is not a bug. This is a future.

        if new_finding.is_mitigated:
            # New finding is mitigated, so mitigate all existing location refs
            self.chunk_locations_and_mitigate(existing_finding.locations.all(), user)
        else:
            # New finding not mitigated; so, reactivate all refs
            existing_location_refs: QuerySet[LocationFindingReference] = existing_finding.locations.all()

            new_locations_values = [str(location) for location in new_finding.unsaved_locations]

            # Reactivate endpoints in the old finding that are in the new finding
            location_refs_to_reactivate = existing_location_refs.filter(location__location_value__in=new_locations_values)
            # Mitigate endpoints in the existing finding not in the new finding
            location_refs_to_mitigate = existing_location_refs.exclude(location__location_value__in=new_locations_values)

            self.chunk_locations_and_reactivate(location_refs_to_reactivate)
            self.chunk_locations_and_mitigate(location_refs_to_mitigate, user)
