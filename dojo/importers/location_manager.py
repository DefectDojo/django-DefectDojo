from __future__ import annotations

import logging
from itertools import groupby
from operator import itemgetter
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db.models import signals
from django.utils import timezone

from dojo.importers.base_location_manager import BaseLocationManager
from dojo.location.models import AbstractLocation, Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.tags_signals import make_inherited_tags_sticky
from dojo.tools.locations import LocationData
from dojo.url.models import URL
from dojo.utils import get_system_setting

if TYPE_CHECKING:
    from dojo.models import Dojo_User, Finding, Product

logger = logging.getLogger(__name__)


# Unsaved locations coming from parsers. These might be existing AbstractLocations (when linking
# existing endpoints) or LocationData objects sent by the parser.
UnsavedLocation = LocationData | AbstractLocation


class LocationManager(BaseLocationManager):

    def __init__(self, product: Product) -> None:
        super().__init__(product)
        self._locations_by_finding: dict[Finding, list[UnsavedLocation]] = {}
        # Product-only locations (not tied to a finding). Appended to by record_locations_for_product.
        self._product_locations: list[UnsavedLocation] = []
        # Status update inputs (deferred). All entries are processed in a single bulk pass by persist().
        # (existing_finding, new_finding, user): classified partial mitigate/reactivate
        self._status_updates: list[tuple[Finding, Finding, Dojo_User]] = []
        # finding_id: fully reactivate (all mitigated refs on this finding become active)
        self._finding_ids_to_fully_reactivate: list[int] = []
        # finding_id -> user: fully mitigate (all non-special refs on this finding become mitigated by user).
        # If recorded multiple times for the same finding, last user wins.
        self._finding_ids_to_fully_mitigate: dict[int, Dojo_User | None] = {}
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
        """Record locations to be associated with a finding (and its product). Flushed by persist()."""
        if locations:
            self._locations_by_finding.setdefault(finding, []).extend(locations)
            self._product_locations.extend(locations)

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
        self._finding_ids_to_fully_mitigate[finding.id] = user

    def get_locations_for_tagging(self, findings: list[Finding]):
        """Return queryset of locations to apply tags to."""
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
        """Persist all accumulated location operations to the database."""
        self._persist_locations()
        self._persist_status_updates()

    def _persist_locations(self) -> None:
        """Bulk get/create all locations and their finding/product refs."""
        # _product_locations contains all locations to persist: associate with finding -> associate with product
        if not self._product_locations:
            return

        # Convert all UnsavedLocation objects (possibly a mix of AbstractLocation and LocationData objects) to cleaned
        # concrete location objects
        all_locations = self.clean_unsaved_locations(self._product_locations)
        if not all_locations:
            self._locations_by_finding.clear()
            self._product_locations.clear()
            return

        # Bulk persist all locations to the database
        saved = self._bulk_get_or_create_locations(all_locations)

        # Build a lookup from (type, identity_hash) -> saved location for finding ref creation.
        # identity_hash is only unique per concrete type, so we key by both.
        #
        # Finding/location mapping was tracked separately in _locations_by_finding which are still the raw
        # UnsavedLocation objects; we'll need to line them up with the persisted locations.
        saved_by_key: dict[tuple[type, str], AbstractLocation] = {
            (type(loc), loc.identity_hash): loc for loc in saved
        }

        # Lists for bulk creation
        all_finding_refs = []
        all_product_refs = []
        # List of all location IDs, for querying existing refs
        all_location_ids = [loc.location_id for loc in saved]

        # Determine necessary product refs to create
        existing_product_refs: set[int] = set(
            LocationProductReference.objects.filter(
                location_id__in=all_location_ids,
                product=self._product,
            ).values_list("location_id", flat=True),
        )
        for location in saved:
            if location.location_id not in existing_product_refs:
                assoc = location.get_association_data()
                all_product_refs.append(LocationProductReference(
                    location_id=location.location_id,
                    product=self._product,
                    status=ProductLocationStatus.Active,
                    relationship=assoc.relationship_type,
                    relationship_data=assoc.relationship_data,
                ))
                existing_product_refs.add(location.location_id)

        # Determine necessary finding refs to create
        if self._locations_by_finding:
            all_finding_ids = [finding.id for finding in self._locations_by_finding]
            # Strictly speaking this returns more rows than we need (it's the cross of the location/finding lists rather
            # than scoped per-finding), but more straightforward than constructing a per-finding lookup. We won't create
            # any unwanted associations below anyway.
            existing_finding_ref_keys: set[tuple[int, int]] = set(
                LocationFindingReference.objects.filter(
                    location_id__in=all_location_ids,
                    finding_id__in=all_finding_ids,
                ).values_list("finding_id", "location_id"),
            )

            for finding, unsaved_locations in self._locations_by_finding.items():
                # Clean per-finding UnsavedLocations to get cleaned AbstractLocations with identity_hashes. The
                # identity_hash uniquely defines the location per type, so using these we can match up with actual
                # persisted locations from above, all of which will be represented in saved_by_key. (Keep in mind,
                # _locations_by_finding contains a subset of the locations across all its values in
                # _locations_by_finding.)
                for location in self.clean_unsaved_locations(unsaved_locations):
                    saved_loc = saved_by_key[type(location), location.identity_hash]
                    finding_ref_key = (finding.id, saved_loc.location_id)
                    if finding_ref_key not in existing_finding_ref_keys:
                        assoc = saved_loc.get_association_data()
                        all_finding_refs.append(LocationFindingReference(
                            location_id=saved_loc.location_id,
                            finding=finding,
                            status=FindingLocationStatus.Active,
                            relationship=assoc.relationship_type,
                            relationship_data=assoc.relationship_data,
                        ))
                        existing_finding_ref_keys.add(finding_ref_key)

        # Bulk create references
        if all_finding_refs:
            LocationFindingReference.objects.bulk_create(
                all_finding_refs, batch_size=1000, ignore_conflicts=True,
            )
        if all_product_refs:
            LocationProductReference.objects.bulk_create(
                all_product_refs, batch_size=1000, ignore_conflicts=True,
            )

        # Trigger bulk tag inheritance
        if self._should_inherit_product_tags():
            self._bulk_inherit_tags(
                (loc.location for loc in saved),
                known_product=self._product,
            )

        # Clear accumulators
        self._locations_by_finding.clear()
        self._product_locations.clear()

    def _persist_status_updates(self) -> None:
        """Bulk persist recorded finding/product ref statuses."""
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

        # Reactivate all mitigated refs for these findings
        if self._finding_ids_to_fully_reactivate:
            ref_ids_to_reactivate.update(
                LocationFindingReference.objects.filter(
                    finding_id__in=self._finding_ids_to_fully_reactivate,
                    status=FindingLocationStatus.Mitigated,
                ).values_list("id", flat=True),
            )

        # Mitigate all non-special refs for these findings, per user
        if self._finding_ids_to_fully_mitigate:
            # Group finding_ids by user to do one SELECT per user
            ids_by_user: dict[Dojo_User | None, list[int]] = {}
            for finding_id, user in self._finding_ids_to_fully_mitigate.items():
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
        """
        Bulk get-or-create a (possibly heterogeneous) list of AbstractLocations.

        The input list may contain a mix of AbstractLocation instances. This method
        groups them by concrete type, delegates each group to that type's bulk_get_or_create,
        then reassembles results in the original input order.
        """
        if not locations:
            return []

        # Keying function: group by the (Python) identity of the concrete class (e.g., URL vs Dependency).
        # Using id() because class objects aren't sortable.
        def type_id(x: tuple[int, AbstractLocation]) -> int:
            return id(type(x[1]))

        saved = []
        # Sort by type, tracking the original index via enumerate so we can restore order later
        locations_with_idx = sorted(enumerate(locations), key=type_id)
        # Now group by type
        locations_by_type = groupby(locations_with_idx, key=type_id)
        for _, grouped_locations_with_idx in locations_by_type:
            # Split into parallel lists: original indices and the homogeneous location objects
            indices, grouped_locations = zip(*grouped_locations_with_idx, strict=True)
            # Determine the concrete AbstractLocation subclass (URL, Dependency, etc.)
            loc_cls = type(grouped_locations[0])
            # Delegate to the per-type bulk_get_or_create on AbstractLocation
            saved_locations = loc_cls.bulk_get_or_create(grouped_locations)
            # Pair each result back with its original index
            saved.extend((idx, saved_loc) for idx, saved_loc in zip(indices, saved_locations, strict=True))

        # Restore the original input ordering
        saved.sort(key=itemgetter(0))
        return [loc for _, loc in saved]

    # ------------------------------------------------------------------
    # Tag inheritance
    # ------------------------------------------------------------------

    @staticmethod
    def _bulk_inherit_tags(locations, *, known_product=None):
        """
        Bulk equivalent of calling inherit_instance_tags(loc) for many Locations.

        Uses aggressive prefetching to produce O(1) queries for the "decide what needs
        to change" phase, and only runs per-instance mutation queries (~3 each) for
        locations that are actually out of sync with their product tags.

        Compared to the per-instance path, this avoids the N expensive JOINs in
        Location.all_related_products() (~50ms each).

        Args:
            locations: iterable of Location instances to update
            known_product: optional hint — if provided, used as the minimum product
                set for locations not already associated elsewhere. Not strictly
                required for correctness, but lets us skip the fetch-related-products
                query in the common case.

        """
        from dojo.models import Product, _manage_inherited_tags  # noqa: PLC0415

        locations = list(locations)
        if not locations:
            return

        system_wide_inherit = bool(get_system_setting("enable_product_tag_inheritance"))

        # --- Bulk query: map location_id -> set[product_id] for every related product
        location_ids = [loc.id for loc in locations]
        product_ids_by_location: dict[int, set[int]] = {loc.id: set() for loc in locations}

        # Path 1: via LocationProductReference (direct association)
        for loc_id, prod_id in LocationProductReference.objects.filter(
            location_id__in=location_ids,
        ).values_list("location_id", "product_id"):
            product_ids_by_location[loc_id].add(prod_id)

        # Path 2: via LocationFindingReference -> Finding -> Test -> Engagement -> Product
        for loc_id, prod_id in (
            LocationFindingReference.objects
            .filter(location_id__in=location_ids)
            .values_list("location_id", "finding__test__engagement__product_id")
        ):
            if prod_id is not None:
                product_ids_by_location[loc_id].add(prod_id)

        # Seed with known_product so callers don't have to rely on refs being persisted before this call
        if known_product is not None:
            for loc_id in location_ids:
                product_ids_by_location[loc_id].add(known_product.id)

        # --- Bulk query: fetch the unique products with their tags and inheritance flag
        all_product_ids = {pid for pids in product_ids_by_location.values() for pid in pids}
        if not all_product_ids:
            return

        products = {
            p.id: p
            for p in Product.objects.filter(id__in=all_product_ids).prefetch_related("tags")
        }

        # Products that contribute to inheritance (either opted in themselves or system-wide on)
        contributing_product_ids = {
            pid for pid, p in products.items()
            if p.enable_product_tag_inheritance or system_wide_inherit
        }
        if not contributing_product_ids:
            return

        # Pre-compute the tag names each contributing product contributes
        tags_by_product: dict[int, set[str]] = {
            pid: {t.name for t in products[pid].tags.all()}
            for pid in contributing_product_ids
        }

        # --- Bulk query: existing inherited_tags per location
        inherited_through = Location.inherited_tags.through
        inherited_fk = Location.inherited_tags.field.m2m_reverse_field_name()
        existing_inherited_by_location: dict[int, set[str]] = {loc.id: set() for loc in locations}
        for loc_id, tag_name in inherited_through.objects.filter(
            location_id__in=location_ids,
        ).values_list("location_id", f"{inherited_fk}__name"):
            existing_inherited_by_location[loc_id].add(tag_name)

        # --- Bulk query: existing user tags per location (needed by _manage_inherited_tags)
        tags_through = Location.tags.through
        tags_fk = Location.tags.field.m2m_reverse_field_name()
        existing_tags_by_location: dict[int, list[str]] = {loc.id: [] for loc in locations}
        for loc_id, tag_name in tags_through.objects.filter(
            location_id__in=location_ids,
        ).values_list("location_id", f"{tags_fk}__name"):
            existing_tags_by_location[loc_id].append(tag_name)

        # --- Determine which locations are out of sync and call _manage_inherited_tags directly.
        # Must disconnect make_inherited_tags_sticky while we mutate — otherwise each
        # tags.set() / inherited_tags.set() fires m2m_changed, re-enters the whole expensive
        # chain per location, and defeats the point of the bulk path.
        # Only disconnect/reconnect for senders where the signal is actually registered
        # (tags.through). inherited_tags.through is not a registered sender — attempting
        # to connect it after disconnect() would incorrectly add a new registration,
        # causing recursion on subsequent calls.
        disconnected = signals.m2m_changed.disconnect(make_inherited_tags_sticky, sender=tags_through)
        try:
            for location in locations:
                target_tag_names: set[str] = set()
                for pid in product_ids_by_location[location.id]:
                    if pid in contributing_product_ids:
                        target_tag_names |= tags_by_product[pid]

                existing = existing_inherited_by_location[location.id]
                if target_tag_names == existing:
                    continue

                _manage_inherited_tags(
                    location,
                    list(target_tag_names),
                    potentially_existing_tags=existing_tags_by_location[location.id],
                )
        finally:
            if disconnected:
                signals.m2m_changed.connect(make_inherited_tags_sticky, sender=tags_through)
