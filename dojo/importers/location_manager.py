from __future__ import annotations

import logging
from itertools import groupby
from operator import itemgetter
from typing import TYPE_CHECKING, TypeVar

from django.core.exceptions import ValidationError
from django.utils import timezone

from dojo.celery import app
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.location.models import AbstractLocation, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.tools.locations import LocationData
from dojo.url.models import URL

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from dojo.models import Dojo_User, Finding, Product

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
    def get_supported_location_types(cls) -> dict[str, type[AbstractLocation]]:
        """Return a mapping of location type string to AbstractLocation subclass."""
        return {URL.get_location_type(): URL}

    @classmethod
    def make_abstract_locations(cls, locations: list[UnsavedLocation]) -> list[AbstractLocation]:
        """Converts the list of unsaved locations (AbstractLocation/LocationData objects) to a list of AbstractLocations."""
        supported_types = cls.get_supported_location_types()
        abstract_locations = []

        for location in locations:
            if isinstance(location, AbstractLocation):
                abstract_locations.append(location)
            elif isinstance(location, LocationData) and (loc_cls := supported_types.get(location.type)):
                try:
                    abstract_locations.append(loc_cls.from_location_data(location))
                except (ValidationError, ValueError):
                    logger.debug("Skipping invalid location data: %s", location)
            else:
                logger.debug(f"Could not create AbstractLocation from type: {type(location)}")

        return abstract_locations

    @classmethod
    def bulk_get_or_create_locations(cls, locations: list[UnsavedLocation]) -> list[AbstractLocation]:
        """Bulk get-or-create a (possibly heterogeneous) list of AbstractLocations."""
        locations = cls.clean_unsaved_locations(locations)
        if not locations:
            return []

        # Util method for sorting/keying; returns the (Python) identity of the location entry's Type
        def type_id(x: tuple[int, AbstractLocation]) -> int:
            return id(type(x[1]))

        saved = []
        # Group by actual AbstractLocation subtype, tracking the original ordering (hence the `enumerate`)
        locations_with_idx = sorted(enumerate(locations), key=type_id)
        locations_by_type = groupby(locations_with_idx, key=type_id)
        for _, grouped_locations_with_idx in locations_by_type:
            # Split into two lists: indices and homogenous location types
            indices, grouped_locations = zip(*grouped_locations_with_idx, strict=True)
            # Determine the correct AbstractLocation class to use for bulk get/create
            loc_cls = type(grouped_locations[0])
            saved_locations = loc_cls.bulk_get_or_create(grouped_locations)
            # Zip 'em back together: associate the saved instance with its original index in the `locations` list
            saved.extend((idx, saved_loc) for idx, saved_loc in zip(indices, saved_locations, strict=True))

        # Sort by index to return in original order
        saved.sort(key=itemgetter(0))
        return [loc for _, loc in saved]

    @classmethod
    def bulk_create_refs(
        cls,
        locations: list[AbstractLocation],
        *,
        finding: Finding | None = None,
        product: Product | None = None,
    ) -> None:
        """
        Bulk create LocationFindingReference and/or LocationProductReference rows.

        Iterates the unsaved/saved pairs once, building both finding and product
        refs in a single pass. Skips refs that already exist in the DB.
        """
        if not locations:
            return

        if not finding and not product:
            error_message = "One of 'finding' or 'product' must be provided."
            raise ValueError(error_message)

        if finding:
            # If associating with a finding, use its product regardless of whatever's set. Keeps in line with the
            # original intended purpose: this is a bulk version of Location.(associate_with_finding|associate_with_product)
            product = finding.test.engagement.product

        location_ids = [loc.location_id for loc in locations]

        # Pre-fetch existing refs to avoid duplicates
        existing_finding_refs = set()
        existing_product_refs = set()
        if finding is not None:
            existing_finding_refs = set(
                LocationFindingReference.objects.filter(
                    location_id__in=location_ids,
                    finding=finding,
                ).values_list("location_id", flat=True),
            )
        if product is not None:
            existing_product_refs = set(
                LocationProductReference.objects.filter(
                    location_id__in=location_ids,
                    product=product,
                ).values_list("location_id", flat=True),
            )

        new_finding_refs = []
        new_product_refs = []
        for location in locations:
            assoc = location.get_association_data()

            if finding is not None and location.location_id not in existing_finding_refs:
                new_finding_refs.append(LocationFindingReference(
                    location_id=location.location_id,
                    finding=finding,
                    status=FindingLocationStatus.Active,
                    relationship=assoc.relationship_type,
                    relationship_data=assoc.relationship_data,
                ))
                existing_finding_refs.add(location.location_id)

            if product is not None and location.location_id not in existing_product_refs:
                new_product_refs.append(LocationProductReference(
                    location_id=location.location_id,
                    product=product,
                    status=ProductLocationStatus.Active,
                    relationship=assoc.relationship_type,
                    relationship_data=assoc.relationship_data,
                ))
                existing_product_refs.add(location.location_id)

        if new_finding_refs:
            LocationFindingReference.objects.bulk_create(
                new_finding_refs, batch_size=1000, ignore_conflicts=True,
            )
        if new_product_refs:
            LocationProductReference.objects.bulk_create(
                new_product_refs, batch_size=1000, ignore_conflicts=True,
            )

    @classmethod
    def _add_locations_to_unsaved_finding(
        cls,
        finding: Finding,
        locations: list[UnsavedLocation],
        **kwargs: dict,  # noqa: ARG003
    ) -> None:
        """Creates AbstractLocation objects from the given list and links them to the given Finding and its Product."""
        locations = cls.bulk_get_or_create_locations(locations)
        cls.bulk_create_refs(locations, finding=finding)
        logger.debug(f"LocationManager: {len(locations)} locations associated with {finding}")

    @app.task
    def add_locations_to_unsaved_finding(
        manager_cls_path: str,  # noqa: N805
        finding: Finding,
        locations: list[UnsavedLocation],
        **kwargs: dict,
    ) -> None:
        """Celery task that resolves the LocationManager class and delegates to _add_locations_to_unsaved_finding."""
        from django.utils.module_loading import import_string  # noqa: PLC0415

        manager_cls = import_string(manager_cls_path)
        manager_cls._add_locations_to_unsaved_finding(finding, locations, **kwargs)

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
        existing_location_refs: QuerySet[LocationFindingReference] = existing_finding.locations.exclude(
            status__in=[
                FindingLocationStatus.FalsePositive,
                FindingLocationStatus.RiskAccepted,
                FindingLocationStatus.OutOfScope,
            ],
        )
        if new_finding.is_mitigated:
            # New finding is mitigated, so mitigate all existing location refs
            self.chunk_locations_and_mitigate(existing_location_refs, user)
        else:
            new_locations_values = [str(location) for location in type(self).clean_unsaved_locations(new_finding.unsaved_locations)]
            # Reactivate endpoints in the old finding that are in the new finding
            location_refs_to_reactivate = existing_location_refs.filter(location__location_value__in=new_locations_values)
            # Mitigate endpoints in the existing finding not in the new finding
            location_refs_to_mitigate = existing_location_refs.exclude(location__location_value__in=new_locations_values)

            self.chunk_locations_and_reactivate(location_refs_to_reactivate)
            self.chunk_locations_and_mitigate(location_refs_to_mitigate, user)

    def chunk_locations_and_disperse(
        self,
        finding: Finding,
        locations: list[UnsavedLocation],
        **kwargs: dict,
    ) -> None:
        if not locations:
            return
        cls_path = f"{type(self).__module__}.{type(self).__qualname__}"
        dojo_dispatch_task(self.add_locations_to_unsaved_finding, cls_path, finding, locations, sync=True)

    def chunk_locations_and_reactivate(
        self,
        location_refs: QuerySet[LocationFindingReference],
        **kwargs: dict,
    ) -> None:
        dojo_dispatch_task(self.reactivate_location_status, location_refs, sync=True)

    def chunk_locations_and_mitigate(
        self,
        location_refs: QuerySet[LocationFindingReference],
        user: Dojo_User,
        **kwargs: dict,
    ) -> None:
        dojo_dispatch_task(self.mitigate_location_status, location_refs, user, sync=True)
