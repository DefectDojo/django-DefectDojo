from __future__ import annotations

import logging
from itertools import groupby
from operator import itemgetter
from typing import TYPE_CHECKING, TypeVar

from django.core.exceptions import ValidationError
from django.utils import timezone

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


class LocationManager:

    def __init__(self, product: Product) -> None:
        self._product = product
        self._locations_by_finding: dict[int, tuple[Finding, list[UnsavedLocation]]] = {}
        self._product_locations: list[UnsavedLocation] = []
        self._refs_to_mitigate: list[tuple[QuerySet[LocationFindingReference], Dojo_User]] = []
        self._refs_to_reactivate: list[QuerySet[LocationFindingReference]] = []

    # ------------------------------------------------------------------
    # Accumulation methods (no DB hits)
    # ------------------------------------------------------------------

    def record_locations_for_finding(
        self,
        finding: Finding,
        locations: list[UnsavedLocation],
    ) -> None:
        """Record locations to be associated with a finding. Flushed by persist()."""
        if locations:
            self._locations_by_finding.setdefault(finding.id, (finding, []))[1].extend(locations)

    def update_location_status(
        self,
        existing_finding: Finding,
        new_finding: Finding,
        user: Dojo_User,
    ) -> None:
        """Accumulate mitigate/reactivate operations for persist()."""
        existing_location_refs: QuerySet[LocationFindingReference] = existing_finding.locations.exclude(
            status__in=[
                FindingLocationStatus.FalsePositive,
                FindingLocationStatus.RiskAccepted,
                FindingLocationStatus.OutOfScope,
            ],
        )
        if new_finding.is_mitigated:
            self._refs_to_mitigate.append((existing_location_refs, user))
        else:
            new_locations_values = [
                str(location) for location in type(self).clean_unsaved_locations(new_finding.unsaved_locations)
            ]
            self._refs_to_reactivate.append(
                existing_location_refs.filter(location__location_value__in=new_locations_values),
            )
            self._refs_to_mitigate.append((
                existing_location_refs.exclude(location__location_value__in=new_locations_values),
                user,
            ))

    def record_reactivations(self, location_refs: QuerySet[LocationFindingReference]) -> None:
        """Record location refs to reactivate. Flushed by persist()."""
        self._refs_to_reactivate.append(location_refs)

    # ------------------------------------------------------------------
    # Unified interface (shared with EndpointManager)
    # ------------------------------------------------------------------

    def clean_unsaved(self, finding: Finding) -> None:
        """Clean the unsaved locations on this finding."""
        type(self).clean_unsaved_locations(finding.unsaved_locations)

    def record_for_finding(self, finding: Finding, extra_items: list[UnsavedLocation] | None = None) -> None:
        """Record locations from the finding + any form-added extras for later batch creation."""
        self.record_locations_for_finding(finding, finding.unsaved_locations)
        if extra_items:
            self.record_locations_for_finding(finding, extra_items)

    def update_status(self, existing_finding: Finding, new_finding: Finding, user: Dojo_User) -> None:
        """Accumulate status changes (mitigate/reactivate) based on old vs new finding."""
        self.update_location_status(existing_finding, new_finding, user)

    def record_reactivations_for_finding(self, finding: Finding) -> None:
        """Record mitigated location refs on this finding for reactivation."""
        mitigated = finding.locations.filter(status=FindingLocationStatus.Mitigated)
        self._refs_to_reactivate.append(mitigated)

    def record_mitigations_for_finding(self, finding: Finding, user: Dojo_User | None = None) -> None:
        """Record all location refs on this finding for mitigation."""
        self._refs_to_mitigate.append((finding.locations.all(), user))

    def get_items_for_tagging(self, findings: list[Finding]):
        """Return queryset of items to apply tags to."""
        from dojo.location.models import Location  # noqa: PLC0415
        return Location.objects.filter(findings__finding__in=findings).distinct()

    def get_item_tag_fallback(self, finding: Finding):
        """Return iterable of taggable items for per-instance fallback."""
        return [ref.location for ref in finding.locations.all()]

    def serialize_extra_items(self, items: list) -> dict:
        """Serialize extra items for import history."""
        return {"locations": [str(loc) for loc in items]} if items else {}

    # ------------------------------------------------------------------
    # Persist — flush all accumulated operations to DB
    # ------------------------------------------------------------------

    def persist(self, user: Dojo_User | None = None) -> None:
        """Flush all accumulated location operations to the database."""
        # Step 1: Collect all locations across all findings, bulk get/create, bulk create refs
        if self._locations_by_finding:
            all_locations: list[AbstractLocation] = []
            finding_ranges: list[tuple[Finding, int, int]] = []

            for finding, locations in self._locations_by_finding.values():
                cleaned = type(self).clean_unsaved_locations(locations)
                start = len(all_locations)
                all_locations.extend(cleaned)
                end = len(all_locations)
                if start < end:
                    finding_ranges.append((finding, start, end))

            if all_locations:
                saved = type(self)._bulk_get_or_create_locations(all_locations)

                # Build all refs across all findings in one pass
                all_finding_refs = []
                all_product_refs = []

                # Pre-fetch existing product refs for this product across all locations
                all_location_ids = [loc.location_id for loc in saved]
                existing_product_refs = set(
                    LocationProductReference.objects.filter(
                        location_id__in=all_location_ids,
                        product=self._product,
                    ).values_list("location_id", flat=True),
                )

                for finding, start, end in finding_ranges:
                    finding_locations = saved[start:end]
                    finding_location_ids = [loc.location_id for loc in finding_locations]

                    existing_finding_refs = set(
                        LocationFindingReference.objects.filter(
                            location_id__in=finding_location_ids,
                            finding=finding,
                        ).values_list("location_id", flat=True),
                    )

                    for location in finding_locations:
                        assoc = location.get_association_data()

                        if location.location_id not in existing_finding_refs:
                            all_finding_refs.append(LocationFindingReference(
                                location_id=location.location_id,
                                finding=finding,
                                status=FindingLocationStatus.Active,
                                relationship=assoc.relationship_type,
                                relationship_data=assoc.relationship_data,
                            ))
                            existing_finding_refs.add(location.location_id)

                        if location.location_id not in existing_product_refs:
                            all_product_refs.append(LocationProductReference(
                                location_id=location.location_id,
                                product=self._product,
                                status=ProductLocationStatus.Active,
                                relationship=assoc.relationship_type,
                                relationship_data=assoc.relationship_data,
                            ))
                            existing_product_refs.add(location.location_id)

                if all_finding_refs:
                    LocationFindingReference.objects.bulk_create(
                        all_finding_refs, batch_size=1000, ignore_conflicts=True,
                    )
                if all_product_refs:
                    LocationProductReference.objects.bulk_create(
                        all_product_refs, batch_size=1000, ignore_conflicts=True,
                    )

                # bulk_create bypasses post_save signals, so manually trigger tag inheritance on each unique Location
                from dojo.tags_signals import inherit_instance_tags  # noqa: PLC0415
                seen_location_ids: set[int] = set()
                for loc in saved:
                    if loc.location_id not in seen_location_ids:
                        seen_location_ids.add(loc.location_id)
                        inherit_instance_tags(loc.location)

            self._locations_by_finding.clear()

        # Step 1b: Product-level locations (not tied to a finding)
        if self._product_locations:
            cleaned = type(self).clean_unsaved_locations(self._product_locations)
            if cleaned:
                saved = type(self)._bulk_get_or_create_locations(cleaned)
                location_ids = [loc.location_id for loc in saved]
                existing = set(
                    LocationProductReference.objects.filter(
                        location_id__in=location_ids,
                        product=self._product,
                    ).values_list("location_id", flat=True),
                )
                new_refs = []
                for location in saved:
                    if location.location_id not in existing:
                        assoc = location.get_association_data()
                        new_refs.append(LocationProductReference(
                            location_id=location.location_id,
                            product=self._product,
                            status=ProductLocationStatus.Active,
                            relationship=assoc.relationship_type,
                            relationship_data=assoc.relationship_data,
                        ))
                        existing.add(location.location_id)
                if new_refs:
                    LocationProductReference.objects.bulk_create(
                        new_refs, batch_size=1000, ignore_conflicts=True,
                    )

                # bulk_create bypasses post_save signals; manually trigger tag inheritance
                from dojo.tags_signals import inherit_instance_tags  # noqa: PLC0415
                for loc in saved:
                    inherit_instance_tags(loc.location)
            self._product_locations.clear()

        # Step 2: Mitigate accumulated refs
        for refs, mitigate_user in self._refs_to_mitigate:
            refs.exclude(status=FindingLocationStatus.Mitigated).update(
                auditor=mitigate_user,
                audit_time=timezone.now(),
                status=FindingLocationStatus.Mitigated,
            )
        self._refs_to_mitigate.clear()

        # Step 3: Reactivate accumulated refs
        for refs in self._refs_to_reactivate:
            refs.filter(status=FindingLocationStatus.Mitigated).update(
                auditor=None,
                audit_time=timezone.now(),
                status=FindingLocationStatus.Active,
            )
        self._refs_to_reactivate.clear()

    # ------------------------------------------------------------------
    # Type registry
    # ------------------------------------------------------------------

    @classmethod
    def get_supported_location_types(cls) -> dict[str, type[AbstractLocation]]:
        """Return a mapping of location type string to AbstractLocation subclass."""
        return {URL.get_location_type(): URL}

    # ------------------------------------------------------------------
    # Cleaning / conversion utilities
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Bulk internals
    # ------------------------------------------------------------------

    @classmethod
    def _bulk_get_or_create_locations(cls, locations: list[AbstractLocation]) -> list[AbstractLocation]:
        """Bulk get-or-create a (possibly heterogeneous) list of AbstractLocations."""
        if not locations:
            return []

        def type_id(x: tuple[int, AbstractLocation]) -> int:
            return id(type(x[1]))

        saved = []
        locations_with_idx = sorted(enumerate(locations), key=type_id)
        locations_by_type = groupby(locations_with_idx, key=type_id)
        for _, grouped_locations_with_idx in locations_by_type:
            indices, grouped_locations = zip(*grouped_locations_with_idx, strict=True)
            loc_cls = type(grouped_locations[0])
            saved_locations = loc_cls.bulk_get_or_create(grouped_locations)
            saved.extend((idx, saved_loc) for idx, saved_loc in zip(indices, saved_locations, strict=True))

        saved.sort(key=itemgetter(0))
        return [loc for _, loc in saved]
