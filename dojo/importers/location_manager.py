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
    Endpoint,
    Finding,
)
from dojo.url.models import URL

logger = logging.getLogger(__name__)


EndpointOrURL = TypeVar("EndpointOrURL", Endpoint, URL)


# test_notifications.py: Implement Locations
class LocationManager:
    @staticmethod
    def get_or_create_location(unsaved_location: AbstractLocation) -> AbstractLocation | None:
        if isinstance(unsaved_location, URL):
            return URL.get_or_create_from_object(unsaved_location)
        logger.debug(f"IMPORT_SCAN: Unsupported location type: {type(unsaved_location)}")
        return None

    @app.task
    def add_locations_to_unsaved_finding(
        finding: Finding,  # noqa: N805
        locations: list[AbstractLocation],
        **kwargs: dict,
    ) -> None:
        """Creates Endpoint objects for a single finding and creates the link via the endpoint status"""
        locations = list(set(locations))

        logger.debug(f"IMPORT_SCAN: Adding {len(locations)} locations to finding: {finding}")
        LocationManager.clean_unsaved_locations(locations)

        # LOCATION LOCATION LOCATION
        # TODO: bulk create the finding/product refs...
        locations_saved = 0
        for unsaved_location in locations:
            if saved_location := LocationManager.get_or_create_location(unsaved_location):
                locations_saved += 1
                saved_location.location.associate_with_finding(finding, status=FindingLocationStatus.Active)

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
        locations: list[AbstractLocation],
        **kwargs: dict,
    ) -> None:
        if not locations:
            return
        dojo_dispatch_task(LocationManager.add_locations_to_unsaved_finding, finding, locations, sync=True)

    @staticmethod
    def clean_unsaved_locations(
        locations: list[AbstractLocation],
    ) -> None:
        """
        Clean endpoints that are supplied. For any endpoints that fail this validation
        process, raise a message that broken endpoints are being stored
        """
        for location in locations:
            try:
                location.clean()
            except ValidationError as e:
                logger.warning("DefectDojo is storing broken locations because cleaning wasn't successful: %s", e)

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
