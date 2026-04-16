from __future__ import annotations

import logging
from itertools import groupby
from operator import itemgetter
from typing import TYPE_CHECKING, TypeVar

from django.core.exceptions import ValidationError
from django.utils import timezone

from dojo.importers.base_location_manager import BaseLocationManager
from dojo.location.models import AbstractLocation, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.tags_signals import bulk_inherit_location_tags
from dojo.tools.locations import LocationData
from dojo.url.models import URL
from dojo.utils import get_system_setting

if TYPE_CHECKING:
    from dojo.models import Dojo_User, Finding, Product

logger = logging.getLogger(__name__)


# TypeVar to represent unsaved locations coming from parsers. These might be existing AbstractLocations (when linking
# existing endpoints) or LocationData objects sent by the parser.
UnsavedLocation = TypeVar("UnsavedLocation", LocationData, AbstractLocation)


class LocationManager(BaseLocationManager):

    def __init__(self, product: Product) -> None:
        super().__init__(product)
        self._locations_by_finding: dict[int, tuple[Finding, list[UnsavedLocation]]] = {}
        # Status update inputs (deferred). All entries are processed in a single bulk pass by persist().
        # (existing_finding, new_finding, user): classified partial mitigate/reactivate
        self._status_updates: list[tuple[Finding, Finding, Dojo_User]] = []
        # finding_id: fully reactivate (all mitigated refs on this finding become active)
        self._finding_ids_to_fully_reactivate: list[int] = []
        # (finding_id, user): fully mitigate (all non-special refs on this finding become mitigated by user)
        self._finding_ids_to_fully_mitigate: list[tuple[int, Dojo_User | None]] = []
        # Cached result of _should_inherit_product_tags() — lazily computed and reused across persist() calls
        self._cached_should_inherit_product_tags: bool | None = None

    def _should_inherit_product_tags(self) -> bool:
        """
        Return True if new LocationFindingReference/LocationProductReference creations
        should trigger inherit_instance_tags on the affected locations.

        inherit_instance_tags() runs a complex JOIN query per location (via all_related_products()),
        which is O(N) per bulk persist. We short-circuit when neither the product nor the system
        setting has tag inheritance enabled — in that case, adding a new ref for self._product
        cannot change any location's inherited tags.
        """
        if self._cached_should_inherit_product_tags is None:
            self._cached_should_inherit_product_tags = bool(
                getattr(self._product, "enable_product_tag_inheritance", False)
                or get_system_setting("enable_product_tag_inheritance"),
            )
        return self._cached_should_inherit_product_tags

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
        """Defer status update to persist(). No DB access at record time."""
        self._status_updates.append((existing_finding, new_finding, user))

    # ------------------------------------------------------------------
    # Unified interface (shared with EndpointManager)
    # ------------------------------------------------------------------

    def clean_unsaved(self, finding: Finding) -> None:
        """Clean the unsaved locations on this finding."""
        self.clean_unsaved_locations(finding.unsaved_locations)

    def record_for_finding(self, finding: Finding, extra_locations: list[UnsavedLocation] | None = None) -> None:
        """Record locations from the finding + any form-added extras for later batch creation."""
        self.record_locations_for_finding(finding, finding.unsaved_locations)
        if extra_locations:
            self.record_locations_for_finding(finding, extra_locations)

    def update_status(self, existing_finding: Finding, new_finding: Finding, user: Dojo_User) -> None:
        """Accumulate status changes (mitigate/reactivate) based on old vs new finding."""
        self.update_location_status(existing_finding, new_finding, user)

    def record_reactivations_for_finding(self, finding: Finding) -> None:
        """Defer reactivation to persist(). No DB access at record time."""
        self._finding_ids_to_fully_reactivate.append(finding.id)

    def record_mitigations_for_finding(self, finding: Finding, user: Dojo_User | None = None) -> None:
        """Defer mitigation to persist(). No DB access at record time."""
        self._finding_ids_to_fully_mitigate.append((finding.id, user))

    def get_locations_for_tagging(self, findings: list[Finding]):
        """Return queryset of locations to apply tags to."""
        from dojo.location.models import Location  # noqa: PLC0415
        return Location.objects.filter(findings__finding__in=findings).distinct()

    def get_location_tag_fallback(self, finding: Finding):
        """Return iterable of taggable locations for per-instance fallback."""
        return [ref.location for ref in finding.locations.all()]

    def serialize_extra_locations(self, locations: list) -> dict:
        """Serialize extra locations for import history."""
        return {"locations": [str(loc) for loc in locations]} if locations else {}

    # ------------------------------------------------------------------
    # Persist — flush all accumulated operations to DB
    # ------------------------------------------------------------------

    def persist(self, user: Dojo_User | None = None) -> None:
        """Flush all accumulated location operations to the database."""
        self._persist_finding_locations()
        self._flush_status_updates()

    def _persist_finding_locations(self) -> None:
        """Bulk get/create locations and their finding+product refs."""
        if not self._locations_by_finding:
            return

        all_locations: list[AbstractLocation] = []
        finding_ranges: list[tuple[Finding, int, int]] = []

        for finding, locations in self._locations_by_finding.values():
            cleaned = self.clean_unsaved_locations(locations)
            start = len(all_locations)
            all_locations.extend(cleaned)
            end = len(all_locations)
            if start < end:
                finding_ranges.append((finding, start, end))

        if all_locations:
            saved = self._bulk_get_or_create_locations(all_locations)

            # Build all refs across all findings in one pass
            all_finding_refs = []
            all_product_refs = []
            # Track locations that got new refs — only those need tag inheritance
            locations_needing_inherit: dict[int, AbstractLocation] = {}

            # Pre-fetch existing product refs for this product across all locations (one query)
            all_location_ids = [loc.location_id for loc in saved]
            existing_product_refs: set[int] = set(
                LocationProductReference.objects.filter(
                    location_id__in=all_location_ids,
                    product=self._product,
                ).values_list("location_id", flat=True),
            )

            # Pre-fetch existing finding refs across ALL findings in one query (avoids N+1)
            all_finding_ids = [finding.id for finding, _, _ in finding_ranges]
            existing_finding_ref_keys: set[tuple[int, int]] = set(
                LocationFindingReference.objects.filter(
                    location_id__in=all_location_ids,
                    finding_id__in=all_finding_ids,
                ).values_list("finding_id", "location_id"),
            )

            for finding, start, end in finding_ranges:
                finding_locations = saved[start:end]

                for location in finding_locations:
                    assoc = location.get_association_data()
                    finding_ref_key = (finding.id, location.location_id)

                    if finding_ref_key not in existing_finding_ref_keys:
                        all_finding_refs.append(LocationFindingReference(
                            location_id=location.location_id,
                            finding=finding,
                            status=FindingLocationStatus.Active,
                            relationship=assoc.relationship_type,
                            relationship_data=assoc.relationship_data,
                        ))
                        existing_finding_ref_keys.add(finding_ref_key)
                        locations_needing_inherit[location.location_id] = location

                    if location.location_id not in existing_product_refs:
                        all_product_refs.append(LocationProductReference(
                            location_id=location.location_id,
                            product=self._product,
                            status=ProductLocationStatus.Active,
                            relationship=assoc.relationship_type,
                            relationship_data=assoc.relationship_data,
                        ))
                        existing_product_refs.add(location.location_id)
                        locations_needing_inherit[location.location_id] = location

            if all_finding_refs:
                LocationFindingReference.objects.bulk_create(
                    all_finding_refs, batch_size=1000, ignore_conflicts=True,
                )
            if all_product_refs:
                LocationProductReference.objects.bulk_create(
                    all_product_refs, batch_size=1000, ignore_conflicts=True,
                )

            # bulk_create bypasses post_save signals; trigger tag inheritance only on locations
            # that got new refs (matches original signal-based behavior). Short-circuit if the
            # product has no tag inheritance enabled, and use the bulk variant otherwise to
            # avoid O(N) expensive JOINs via Location.all_related_products().
            if self._should_inherit_product_tags() and locations_needing_inherit:
                bulk_inherit_location_tags(
                    (loc.location for loc in locations_needing_inherit.values()),
                    known_product=self._product,
                )

        self._locations_by_finding.clear()

    def _flush_status_updates(self) -> None:
        """
        Resolve all accumulated status-update inputs and execute them as bulk UPDATEs.

        Produces ~3-4 queries total regardless of the number of findings processed:
        1 SELECT to fetch relevant location refs for partial-status updates,
        1 UPDATE for reactivations,
        1 UPDATE per unique mitigation user (typically 1).
        """
        # Short-circuit if nothing to do
        if not (self._status_updates or self._finding_ids_to_fully_reactivate or self._finding_ids_to_fully_mitigate):
            return

        special_statuses = [
            FindingLocationStatus.FalsePositive,
            FindingLocationStatus.RiskAccepted,
            FindingLocationStatus.OutOfScope,
        ]

        # Collect ref IDs to reactivate / mitigate across all accumulated inputs
        ref_ids_to_reactivate: set[int] = set()
        # Grouped by user since auditor differs per entry
        ref_ids_to_mitigate_by_user: dict[Dojo_User | None, set[int]] = {}

        # Partial status updates (from update_location_status): need per-finding classification
        if self._status_updates:
            finding_ids_for_partial = {upd[0].id for upd in self._status_updates}
            # Single fetch of all candidate refs with their location values
            refs_by_finding: dict[int, list[LocationFindingReference]] = {}
            for ref in (
                LocationFindingReference.objects
                .filter(finding_id__in=finding_ids_for_partial)
                .exclude(status__in=special_statuses)
                .select_related("location")
            ):
                refs_by_finding.setdefault(ref.finding_id, []).append(ref)

            for existing_finding, new_finding, user in self._status_updates:
                finding_refs = refs_by_finding.get(existing_finding.id, [])
                if new_finding.is_mitigated:
                    # All non-special refs on this finding get mitigated
                    ref_ids_to_mitigate_by_user.setdefault(user, set()).update(r.id for r in finding_refs)
                else:
                    new_loc_values = {
                        str(loc) for loc in self.clean_unsaved_locations(new_finding.unsaved_locations)
                    }
                    for ref in finding_refs:
                        if ref.location.location_value in new_loc_values:
                            ref_ids_to_reactivate.add(ref.id)
                        else:
                            ref_ids_to_mitigate_by_user.setdefault(user, set()).add(ref.id)

        # Full reactivations (from record_reactivations_for_finding): all mitigated refs for these findings
        if self._finding_ids_to_fully_reactivate:
            ref_ids_to_reactivate.update(
                LocationFindingReference.objects.filter(
                    finding_id__in=self._finding_ids_to_fully_reactivate,
                    status=FindingLocationStatus.Mitigated,
                ).values_list("id", flat=True),
            )

        # Full mitigations (from record_mitigations_for_finding): all non-special refs for these findings, per user
        if self._finding_ids_to_fully_mitigate:
            # Group finding_ids by user to do one SELECT per user
            ids_by_user: dict[Dojo_User | None, list[int]] = {}
            for finding_id, user in self._finding_ids_to_fully_mitigate:
                ids_by_user.setdefault(user, []).append(finding_id)
            for user, finding_ids in ids_by_user.items():
                ref_ids_to_mitigate_by_user.setdefault(user, set()).update(
                    LocationFindingReference.objects.filter(
                        finding_id__in=finding_ids,
                    ).exclude(status__in=special_statuses).values_list("id", flat=True),
                )

        # Execute bulk updates
        now = timezone.now()
        if ref_ids_to_reactivate:
            LocationFindingReference.objects.filter(
                id__in=ref_ids_to_reactivate,
                status=FindingLocationStatus.Mitigated,
            ).update(
                auditor=None,
                audit_time=now,
                status=FindingLocationStatus.Active,
            )

        for user, ref_ids in ref_ids_to_mitigate_by_user.items():
            if ref_ids:
                LocationFindingReference.objects.filter(
                    id__in=ref_ids,
                ).exclude(status=FindingLocationStatus.Mitigated).update(
                    auditor=user,
                    audit_time=now,
                    status=FindingLocationStatus.Mitigated,
                )

        # Clear accumulators
        self._status_updates.clear()
        self._finding_ids_to_fully_reactivate.clear()
        self._finding_ids_to_fully_mitigate.clear()

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
