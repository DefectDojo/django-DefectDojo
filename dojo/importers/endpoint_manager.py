import logging
from typing import NamedTuple

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from hyperlink._url import SCHEME_PORT_MAP  # noqa: PLC2701

from dojo.importers.base_location_manager import BaseLocationManager
from dojo.models import (
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Finding,
    Product,
)
from dojo.tags_signals import inherit_instance_tags

logger = logging.getLogger(__name__)


class EndpointUniqueKey(NamedTuple):
    protocol: str | None
    userinfo: str | None
    host: str | None
    port: int | None
    path: str | None
    query: str | None
    fragment: str | None
    product_id: int


# TODO: Delete this after the move to Locations
class EndpointManager(BaseLocationManager):

    def __init__(self, product: Product) -> None:
        self._product = product
        self._endpoints_to_create: dict[EndpointUniqueKey, dict] = {}
        self._statuses_to_create: list[tuple[Finding, EndpointUniqueKey]] = []
        self._statuses_to_mitigate: list[tuple[Endpoint_Status, Dojo_User | None]] = []
        self._statuses_to_reactivate: list[Endpoint_Status] = []

    @staticmethod
    def _make_endpoint_unique_tuple(
        protocol: str | None,
        userinfo: str | None,
        host: str | None,
        port: int | None,
        path: str | None,
        query: str | None,
        fragment: str | None,
        product_id: int,
    ) -> EndpointUniqueKey:
        """
        Normalize endpoint fields to a unique key matching endpoint_filter() semantics.

        See dojo/endpoint/utils.py endpoint_filter() for the canonical matching logic.
        """
        norm_protocol = protocol.lower() if protocol else None
        norm_host = host.lower() if host else None

        # Port normalization: if protocol has a default port, treat that port
        # and None as equivalent (matching endpoint_filter's Q(port__isnull=True) | Q(port__exact=default))
        norm_port = port
        if norm_protocol and norm_protocol in SCHEME_PORT_MAP:
            default_port = SCHEME_PORT_MAP[norm_protocol]
            if port is None or port == default_port:
                norm_port = None

        return EndpointUniqueKey(
            protocol=norm_protocol,
            userinfo=userinfo or None,
            host=norm_host,
            port=norm_port,
            path=path or None,
            query=query or None,
            fragment=fragment or None,
            product_id=product_id,
        )

    @staticmethod
    def clean_unsaved_endpoints(
        endpoints: list[Endpoint],
    ) -> None:
        """
        Clean endpoints that are supplied. For any endpoints that fail this validation
        process, raise a message that broken endpoints are being stored.
        """
        for endpoint in endpoints:
            try:
                endpoint.clean()
            except ValidationError as e:
                logger.warning("DefectDojo is storing broken endpoint because cleaning wasn't successful: %s", e)

    def record_endpoint(self, endpoint: Endpoint) -> EndpointUniqueKey:
        """Record an endpoint for later batch creation. Returns the unique key."""
        key = self._make_endpoint_unique_tuple(
            protocol=endpoint.protocol,
            userinfo=endpoint.userinfo,
            host=endpoint.host,
            port=endpoint.port,
            path=endpoint.path,
            query=endpoint.query,
            fragment=endpoint.fragment,
            product_id=self._product.id,
        )
        if key not in self._endpoints_to_create:
            self._endpoints_to_create[key] = {
                "protocol": endpoint.protocol,
                "userinfo": endpoint.userinfo,
                "host": endpoint.host,
                "port": endpoint.port,
                "path": endpoint.path,
                "query": endpoint.query,
                "fragment": endpoint.fragment,
                "product": self._product,
            }
        return key

    def record_status_for_create(self, finding: Finding, key: EndpointUniqueKey) -> None:
        """Record that a finding should be linked to an endpoint (identified by key) via Endpoint_Status."""
        self._statuses_to_create.append((finding, key))

    @staticmethod
    def get_non_special_endpoint_statuses(finding: Finding) -> list[Endpoint_Status]:
        """
        Return endpoint statuses that are not false_positive, out_of_scope, or risk_accepted.

        Uses finding.status_finding.all() which is served from the prefetch cache when the
        finding was loaded through build_candidate_scope_queryset, and falls back to a DB
        query otherwise (e.g. for findings created during the same reimport batch).

        This might be ineffecient if lots of internal duplicates are in the report.
        But this should be limited as most parsers dedupe during parsing and merge the endpoints.
        """
        return [
            eps for eps in finding.status_finding.all()
            if not eps.false_positive and not eps.out_of_scope and not eps.risk_accepted
        ]

    def update_endpoint_status(
        self,
        existing_finding: Finding,
        new_finding: Finding,
        user: Dojo_User,
    ) -> None:
        """
        Compare old/new endpoints and accumulate mitigate/reactivate lists.

        The actual bulk_update happens in persist().
        """
        # New endpoints are already added in serializers.py / views.py (see comment "# for existing findings: make sure endpoints are present or created")
        # So we only need to mitigate endpoints that are no longer present
        # status_finding_non_special is prefetched by build_candidate_scope_queryset with the
        # special-status exclusion and endpoint select_related already applied at the DB level.
        # Falls back to a DB query when the finding was not loaded through that queryset
        # (e.g. a finding created during the same reimport batch).
        existing_finding_endpoint_status_list = self.get_non_special_endpoint_statuses(existing_finding)
        new_finding_endpoints_list = new_finding.unsaved_endpoints
        if new_finding.is_mitigated:
            # New finding is mitigated, so mitigate all old endpoints
            self._statuses_to_mitigate.extend((eps, user) for eps in existing_finding_endpoint_status_list)
        else:
            # Convert to set for O(1) lookups instead of O(n) linear search
            new_finding_endpoints_set = set(new_finding_endpoints_list)
            # Mitigate any endpoints in the old finding not found in the new finding
            self._statuses_to_mitigate.extend(
                (eps, user) for eps in existing_finding_endpoint_status_list
                if eps.endpoint not in new_finding_endpoints_set
            )
            # Re-activate any endpoints in the old finding that are in the new finding
            self._statuses_to_reactivate.extend(
                eps for eps in existing_finding_endpoint_status_list
                if eps.endpoint in new_finding_endpoints_set
            )

    def record_statuses_to_reactivate(self, statuses: list[Endpoint_Status]) -> None:
        """Accumulate endpoint statuses for bulk reactivation in persist()."""
        self._statuses_to_reactivate.extend(statuses)

    def record_statuses_to_mitigate(self, statuses: list[Endpoint_Status], user: Dojo_User | None = None) -> None:
        """Accumulate endpoint statuses for bulk mitigation in persist()."""
        self._statuses_to_mitigate.extend((eps, user) for eps in statuses)

    def get_or_create_endpoints(self) -> tuple[dict[EndpointUniqueKey, Endpoint], list[Endpoint]]:
        """
        For each queued endpoint record, fetch the existing DB row or bulk_create a new one.

        Returns:
            (endpoints_by_key, created) where:
            - endpoints_by_key maps each EndpointUniqueKey to its Endpoint object (existing or new)
            - created is the list of Endpoint objects that were actually inserted into the DB

        """
        if not self._endpoints_to_create:
            return {}, []

        endpoints_by_key: dict[EndpointUniqueKey, Endpoint] = {}

        with transaction.atomic():
            # Fetch all existing endpoints for this product
            for ep in (
                Endpoint.objects.filter(product=self._product)
                .only("id", "protocol", "userinfo", "host", "port", "path", "query", "fragment", "product_id")
                .order_by("id")
                .iterator()
            ):
                key = self._make_endpoint_unique_tuple(
                    protocol=ep.protocol,
                    userinfo=ep.userinfo,
                    host=ep.host,
                    port=ep.port,
                    path=ep.path,
                    query=ep.query,
                    fragment=ep.fragment,
                    product_id=ep.product_id,
                )
                # First-by-id wins, matching endpoint_get_or_create behavior
                if key not in endpoints_by_key:
                    endpoints_by_key[key] = ep

            # Determine which endpoints still need creating
            to_create = []
            to_create_keys = []
            for key, kwargs in self._endpoints_to_create.items():
                if key not in endpoints_by_key:
                    to_create.append(Endpoint(**kwargs))
                    to_create_keys.append(key)

            created: list[Endpoint] = []
            if to_create:
                created = Endpoint.objects.bulk_create(to_create, batch_size=1000)
                endpoints_by_key.update(zip(to_create_keys, created, strict=True))
                # bulk_create bypasses post_save signals, so manually trigger tag inheritance
                # this is not ideal, but we need to take a separate look at the tag inheritance feature itself later
                for ep in created:
                    inherit_instance_tags(ep)

        self._endpoints_to_create.clear()
        return endpoints_by_key, created

    def persist(self) -> None:
        """
        Persist all accumulated endpoint operations to the database.

        Called at batch boundaries during import/reimport.
        """
        # Step 1: Ensure all recorded endpoints exist in DB
        endpoints_by_key, _ = self.get_or_create_endpoints()

        # Step 2: Bulk-create Endpoint_Status rows
        if self._statuses_to_create:
            rows = [
                Endpoint_Status(
                    finding=finding,
                    endpoint=endpoints_by_key[key],
                    date=finding.date,
                )
                for finding, key in self._statuses_to_create
                if key in endpoints_by_key
            ]
            if rows:
                Endpoint_Status.objects.bulk_create(rows, ignore_conflicts=True, batch_size=1000)
            self._statuses_to_create.clear()

        # Step 3: Bulk-update mitigated endpoint statuses
        if self._statuses_to_mitigate:
            now = timezone.now()
            to_update = []
            for endpoint_status, mitigated_by in self._statuses_to_mitigate:
                if endpoint_status.mitigated is False:
                    endpoint_status.mitigated_time = now
                    endpoint_status.last_modified = now
                    endpoint_status.mitigated_by = mitigated_by
                    endpoint_status.mitigated = True
                    to_update.append(endpoint_status)
            if to_update:
                Endpoint_Status.objects.bulk_update(
                    to_update,
                    ["mitigated", "mitigated_time", "last_modified", "mitigated_by"],
                    batch_size=1000,
                )
            self._statuses_to_mitigate.clear()

        # Step 4: Bulk-update reactivated endpoint statuses
        if self._statuses_to_reactivate:
            now = timezone.now()
            to_update = []
            for endpoint_status in self._statuses_to_reactivate:
                if endpoint_status.mitigated:
                    logger.debug("Re-import: reactivating endpoint %s that is present in this scan", endpoint_status.endpoint)
                    endpoint_status.mitigated_by = None
                    endpoint_status.mitigated_time = None
                    endpoint_status.mitigated = False
                    endpoint_status.last_modified = now
                    to_update.append(endpoint_status)
            if to_update:
                Endpoint_Status.objects.bulk_update(
                    to_update,
                    ["mitigated", "mitigated_time", "mitigated_by", "last_modified"],
                    batch_size=1000,
                )
            self._statuses_to_reactivate.clear()

    # ------------------------------------------------------------------
    # Unified interface (shared with LocationManager)
    # ------------------------------------------------------------------

    def clean_unsaved(self, finding: Finding) -> None:
        """Clean the unsaved endpoints on this finding."""
        self.clean_unsaved_endpoints(finding.unsaved_endpoints)

    def record_for_finding(self, finding: Finding, extra_locations: list[Endpoint] | None = None) -> None:
        """Record endpoints from the finding + any form-added extras for later batch creation."""
        self.clean_unsaved_endpoints(finding.unsaved_endpoints)
        for endpoint in finding.unsaved_endpoints:
            key = self.record_endpoint(endpoint)
            self.record_status_for_create(finding, key)
        if extra_locations:
            for endpoint in extra_locations:
                key = self.record_endpoint(endpoint)
                self.record_status_for_create(finding, key)

    def update_status(self, existing_finding: Finding, new_finding: Finding, user: Dojo_User) -> None:
        """Accumulate status changes (mitigate/reactivate) based on old vs new finding."""
        self.update_endpoint_status(existing_finding, new_finding, user)

    def record_reactivations_for_finding(self, finding: Finding) -> None:
        """Record endpoint statuses on this finding for reactivation."""
        self.record_statuses_to_reactivate(self.get_non_special_endpoint_statuses(finding))

    def record_mitigations_for_finding(self, finding: Finding, user: Dojo_User) -> None:
        """Record endpoint statuses on this finding for mitigation."""
        self.record_statuses_to_mitigate(finding.status_finding.all(), user)

    def get_locations_for_tagging(self, findings: list[Finding]):
        """Return queryset of locations to apply tags to."""
        return Endpoint.objects.filter(finding__in=findings).distinct()

    def get_location_tag_fallback(self, finding: Finding):
        """Return iterable of taggable locations for per-instance fallback."""
        return finding.endpoints.all()

    def serialize_extra_locations(self, locations: list) -> dict:
        """Serialize extra locations for import history."""
        return {"endpoints": [str(ep) for ep in locations]} if locations else {}
