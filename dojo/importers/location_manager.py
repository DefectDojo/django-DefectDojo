from __future__ import annotations

import logging
from itertools import groupby
from operator import itemgetter
from typing import TYPE_CHECKING, NamedTuple

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import signals
from django.utils import timezone

from dojo.importers.base_location_manager import BaseLocationManager
from dojo.location.models import AbstractLocation, Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import Product, _manage_inherited_tags
from dojo.tags_signals import make_inherited_tags_sticky
from dojo.tools.locations import LocationData
from dojo.url.models import URL
from dojo.utils import get_system_setting

if TYPE_CHECKING:
    from tagulous.models import TagField

    from dojo.models import Dojo_User, Finding

logger = logging.getLogger(__name__)


# Unsaved locations coming from parsers. These might be existing AbstractLocations (when linking
# existing endpoints) or LocationData objects sent by the parser.
UnsavedLocation = LocationData | AbstractLocation


# Entry for status update; status will be determined by comparing locations between existing and new findings
class StatusUpdateEntry(NamedTuple):
    existing_finding: Finding
    new_finding: Finding
    user: Dojo_User


class LocationManager(BaseLocationManager):

    def __init__(self, product: Product) -> None:
        super().__init__(product)
        # Maps findings to a list of locations
        self._locations_by_finding: dict[Finding, list[UnsavedLocation]] = {}
        # Product-only locations (not tied to a finding)
        self._product_locations: list[UnsavedLocation] = []
        # Status update entries, which we'll use at persist-time to determine Location statuses by comparing
        # existing vs new finding entries.
        self._status_updates: list[StatusUpdateEntry] = []
        # IDs of finding refs to reactivate
        self._refs_to_reactivate: list[int] = []
        # IDs of finding refs to mitigate, by the associated user
        self._refs_to_mitigate: dict[int, Dojo_User] = {}

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
        self._status_updates.append(StatusUpdateEntry(existing_finding, new_finding, user))

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
        self._refs_to_reactivate.append(finding.id)

    def record_mitigations_for_finding(self, finding: Finding, user: Dojo_User) -> None:
        """Defer mitigation to persist(). No DB access at record time."""
        self._refs_to_mitigate[finding.id] = user

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

    def persist(self) -> None:
        """Persist all accumulated location operations to the database."""
        with transaction.atomic():
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
        self._bulk_inherit_tags(loc.location for loc in saved)

        # Clear accumulators
        self._locations_by_finding.clear()
        self._product_locations.clear()

    def _persist_status_updates(self) -> None:
        """
        Bulk persist finding/product ref statuses.

        Throughout the (re)import process, we've tracked three types of status changes: locations to mitigate, locations
        to reactivate, and locations whose statuses need to be evaluated at this time by comparing locations between
        existing findings and new findings.

        To start, this method processes the comparisons between existing/new findings. If the new finding is Mitigated,
        then all existing locations are added to the 'to mitigate' set. Otherwise, locations that are in both the new
        finding and existing finding are added to the 'to reactivate' set, and locations that are on the existing
        finding but not the new finding are added to the 'to mitigate' set.

        Next, all locations in the 'to reactivate' set are bulk set to Active, and all locations in the 'to mitigate'
        set are bulk set to Mitigated.

        Finally, product associations are updated: if any location associated with a finding on this product is Active,
        the LocationProductReference object is set to Active; otherwise, it is set to Mitigated.
        """
        # Short-circuit if nothing to do
        if not (self._status_updates or self._refs_to_reactivate or self._refs_to_mitigate):
            return

        # List of statuses we'll skip processing changes for
        special_statuses = [
            FindingLocationStatus.FalsePositive,
            FindingLocationStatus.RiskAccepted,
            FindingLocationStatus.OutOfScope,
        ]

        # The set of LocationFindingReference IDs to reactivate
        ref_ids_to_reactivate: set[int] = set()
        # The set of LocationFindingReference IDs to mitigate, and the user to associate with it
        ref_ids_to_mitigate: dict[int, Dojo_User] = {}

        # Process status updates determined by comparing existing/new findings
        if self._status_updates:
            # Look up all the existing LocationFindingReference objects and store per-Finding
            existing_finding_ids = {upd.existing_finding.id for upd in self._status_updates}
            refs_by_finding: dict[int, list[LocationFindingReference]] = {}
            for ref in (
                LocationFindingReference.objects
                .filter(finding_id__in=existing_finding_ids)
                .exclude(status__in=special_statuses)
                .select_related("location")
            ):
                refs_by_finding.setdefault(ref.finding_id, []).append(ref)

            # Next: for each StatusUpdateEntry, determine what we should do with the existing refs
            for existing_finding, new_finding, user in self._status_updates:
                finding_refs = refs_by_finding.get(existing_finding.id, [])
                if new_finding.is_mitigated:
                    # The new finding is mitigated, so mitigate all existing (non-special) refs
                    ref_ids_to_mitigate.update({r.id: user for r in finding_refs})
                else:
                    # The new finding is not mitigated; we need to reactivate locations that are in the new finding and
                    # mitigate statuses that are NOT in the new finding.
                    new_loc_values = {
                        str(loc) for loc in self.clean_unsaved_locations(new_finding.unsaved_locations)
                    }
                    for ref in finding_refs:
                        if ref.location.location_value in new_loc_values:
                            ref_ids_to_reactivate.add(ref.id)
                        else:
                            ref_ids_to_mitigate[ref.id] = user

        # Update the "reactivate set" with the IDs of existing LocationFindingReference objects we need to reactivate
        if self._refs_to_reactivate:
            ref_ids_to_reactivate.update(
                LocationFindingReference.objects.filter(
                    finding_id__in=self._refs_to_reactivate,
                    status=FindingLocationStatus.Mitigated,
                ).values_list("id", flat=True),
            )

        # Update the "mitigate set" with the IDs of existing LocationFindingReference objects we need to mitigate.
        # Note we exclude LocationFindingReferences that currently have one of the special statuses.
        if self._refs_to_mitigate:
            ref_ids_to_mitigate.update({
                ref_id: self._refs_to_mitigate[finding_id]
                for ref_id, finding_id in LocationFindingReference.objects.filter(
                    finding_id__in=self._refs_to_mitigate.keys(),
                ).exclude(status__in=special_statuses).values_list("id", "finding_id")
            })

        # Hoorah we finally get around to actually updating stuff
        now = timezone.now()
        # Track all updated LocationFindingReference IDs so we can update the corresponding LocationProductReferences
        # as necessary: if any LocationFindingReference is Active, the LocationProductReferences will be set to Active;
        # otherwise, they will be set to Mitigated.
        all_affected_ref_ids: set[int] = set()

        # Update Mitigated => Active ("reactivate")
        if ref_ids_to_reactivate:
            LocationFindingReference.objects.filter(
                id__in=ref_ids_to_reactivate,
                status=FindingLocationStatus.Mitigated,
            ).update(
                auditor=None,
                audit_time=now,
                status=FindingLocationStatus.Active,
            )
            all_affected_ref_ids |= ref_ids_to_reactivate

        # Update ~Mitigated => Mitigated
        if ref_ids_to_mitigate:
            # Flip (ref_id -> user) to (user -> set[ref_id]) for per-user bulk updates
            ref_ids_per_user: dict[Dojo_User, set[int]] = {}
            for ref_id, user in ref_ids_to_mitigate.items():
                ref_ids_per_user.setdefault(user, set()).add(ref_id)
            # Update per user
            for user, ref_ids in ref_ids_per_user.items():
                LocationFindingReference.objects.filter(
                    id__in=ref_ids,
                ).exclude(
                    status=FindingLocationStatus.Mitigated,
                ).update(
                    auditor=user,
                    audit_time=now,
                    status=FindingLocationStatus.Mitigated,
                )
                all_affected_ref_ids |= ref_ids

        # Propagate to product refs: if any finding ref for this location on this product is Active, product ref is
        # Active; otherwise Mitigated.
        if all_affected_ref_ids:
            # Grab the location IDs for all the LocationFindingReferences we updated
            affected_location_ids = set(
                LocationFindingReference.objects.filter(
                    id__in=all_affected_ref_ids,
                ).values_list("location_id", flat=True),
            )
            # Look up all affected LocationFindingReferences that are now Active and associated with this product
            # through the "finding.test.engagement.product" chain
            locations_still_active = set(
                LocationFindingReference.objects.filter(
                    location_id__in=affected_location_ids,
                    finding__test__engagement__product=self._product,
                    status=FindingLocationStatus.Active,
                ).values_list("location_id", flat=True),
            )
            # Diff the two; this leaves IDs of locations that should be set to Mitigated at the product level
            locations_now_mitigated = affected_location_ids - locations_still_active

            # Update LocationProductReferences to Active for any locations associated with this product that have an
            # Active LocationFindingReference
            if locations_still_active:
                LocationProductReference.objects.filter(
                    location_id__in=locations_still_active,
                    product=self._product,
                ).exclude(status=ProductLocationStatus.Active).update(
                    status=ProductLocationStatus.Active,
                )
            # Update LocationProductReferences to Mitigated for any locations associated with this product that have no
            # Active LocationFindingReferences
            if locations_now_mitigated:
                LocationProductReference.objects.filter(
                    location_id__in=locations_now_mitigated,
                    product=self._product,
                ).exclude(status=ProductLocationStatus.Mitigated).update(
                    status=ProductLocationStatus.Mitigated,
                )

        # Clear accumulators
        self._status_updates.clear()
        self._refs_to_reactivate.clear()
        self._refs_to_mitigate.clear()

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

    def _bulk_inherit_tags(self, locations):
        """
        Bulk equivalent of calling inherit_instance_tags(loc) for many Locations. Actually persisting updates is handled
        by a per-location call to _manage_inherited_tags(), but at least determining what the tags are is more efficient
        (plus we can skip locations that don't need an update at all).

        When tag inheritance is enabled, computes the target inherited tags for each location from all related products
        and updates only locations that are out of sync.
        """
        locations = list(locations)
        if not locations:
            return

        # Check whether tag inheritance is enabled at either the product level or system-wide; quit early if neither
        product_inherit = getattr(self._product, "enable_product_tag_inheritance", False)
        system_wide_inherit = bool(get_system_setting("enable_product_tag_inheritance"))
        if not system_wide_inherit and not product_inherit:
            return

        # A location can be shared across multiple products. Its inherited tags should be the union of
        # tags from ALL contributing products, not just the one running this import.
        location_ids = [loc.id for loc in locations]
        product_ids_by_location: dict[int, set[int]] = {loc.id: set() for loc in locations}

        # Find associations through LocationProductReference entries
        for loc_id, prod_id in LocationProductReference.objects.filter(
            location_id__in=location_ids,
        ).values_list("location_id", "product_id"):
            product_ids_by_location[loc_id].add(prod_id)

        # Find associations through LocationFindingReference entries and the finding.test.engagement.product chain.
        # This shouldn't add anything new, but just in case.
        for loc_id, prod_id in (
            LocationFindingReference.objects
            .filter(location_id__in=location_ids)
            .values_list("location_id", "finding__test__engagement__product_id")
        ):
            product_ids_by_location[loc_id].add(prod_id)

        # Fetch all products that will contribute to tag inheritance, and their tags
        all_product_ids = {pid for pids in product_ids_by_location.values() for pid in pids}
        product_qs = Product.objects.filter(id__in=all_product_ids).prefetch_related("tags")
        if not system_wide_inherit:
            # Product-level inheritance only
            product_qs = product_qs.filter(enable_product_tag_inheritance=True)
        # Materialize into a dict for ease of use
        products: dict[int, Product] = {p.id: p for p in product_qs}
        # Get distinct tags, per-product
        tags_by_product: dict[int, set[str]] = {
            pid: {t.name for t in p.tags.all()}
            for pid, p in products.items()
        }

        # Helper method for getting all tags from the given TagField
        def _get_tags(tags_field: TagField) -> dict[int, set[str]]:
            through_model = tags_field.through
            fk_name = tags_field.field.m2m_reverse_field_name()
            tags_by_location: dict[int, set[str]] = {loc.id: set() for loc in locations}
            for l_id, t_name in through_model.objects.filter(
                location_id__in=location_ids,
            ).values_list("location_id", f"{fk_name}__name"):
                tags_by_location[l_id].add(t_name)
            return tags_by_location

        # Gather inherited and 'regular' tags per location
        existing_inherited_by_location: dict[int, set[str]] = _get_tags(Location.inherited_tags)
        existing_tags_by_location: dict[int, set[str]] = _get_tags(Location.tags)

        # Perform the bulk updates. First, though, disconnect the make_inherited_tags_sticky signal on Location.tags
        # while updating, otherwise each (inherited_)tags.set() will trigger, defeating the purpose of this bulk update.
        disconnected = signals.m2m_changed.disconnect(make_inherited_tags_sticky, sender=Location.tags.through)
        try:
            for location in locations:
                target_tag_names: set[str] = set()
                for pid in product_ids_by_location[location.id]:
                    # product_ids_by_location may contain products that shouldn't to contribute to tag inheritance (we
                    # didn't filter either location ref lookups to check), so do a last-minute check here
                    if pid in products:
                        target_tag_names |= tags_by_product[pid]

                if target_tag_names == existing_inherited_by_location[location.id]:
                    # The existing set matches the expected set, so nothing more to do for this location
                    continue

                # Update tags for this location
                _manage_inherited_tags(
                    location,
                    list(target_tag_names),
                    potentially_existing_tags=existing_tags_by_location[location.id],
                )
        finally:
            if disconnected:
                signals.m2m_changed.connect(make_inherited_tags_sticky, sender=Location.tags.through)
