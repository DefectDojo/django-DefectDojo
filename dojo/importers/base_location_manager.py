"""
Base class and handler for location/endpoint managers in the import pipeline.

BaseLocationManager defines the contract that both LocationManager (V3) and
EndpointManager (legacy) must implement. LocationHandler is the facade that
importers interact with — it picks the appropriate manager based on
V3_FEATURE_LOCATIONS and delegates all calls through the shared interface.

This structure prevents drift between the two managers: adding an abstract
method to BaseLocationManager forces both to implement it, and callers can
only access methods exposed by LocationHandler.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dojo.models import Dojo_User, Finding, Product


class BaseLocationManager(ABC):

    """
    Abstract base for import-pipeline managers that handle network identifiers
    (locations in V3, endpoints in legacy).

    Subclasses must implement every abstract method. The importer never calls
    subclass-specific methods directly — it goes through LocationHandler.
    """

    def __init__(self, product: Product) -> None:
        self._product = product

    @abstractmethod
    def clean_unsaved(self, finding: Finding) -> None:
        """Clean the unsaved locations/endpoints on this finding."""

    @abstractmethod
    def record_for_finding(self, finding: Finding, extra_locations: list | None = None) -> None:
        """Record items from the finding + any form-added extras for later batch creation."""

    @abstractmethod
    def update_status(self, existing_finding: Finding, new_finding: Finding, user: Dojo_User) -> None:
        """Accumulate status changes (mitigate/reactivate) based on old vs new finding."""

    @abstractmethod
    def record_reactivations_for_finding(self, finding: Finding) -> None:
        """Record items on this finding for reactivation."""

    @abstractmethod
    def record_mitigations_for_finding(self, finding: Finding, user: Dojo_User | None = None) -> None:
        """Record items on this finding for mitigation."""

    @abstractmethod
    def get_locations_for_tagging(self, findings: list[Finding]):
        """Return a queryset of taggable objects linked to the given findings."""

    @abstractmethod
    def get_location_tag_fallback(self, finding: Finding):
        """Return an iterable of taggable objects for per-instance tag fallback."""

    @abstractmethod
    def serialize_extra_locations(self, locations: list) -> dict:
        """Serialize extra locations/endpoints for import history settings."""

    @abstractmethod
    def persist(self, user: Dojo_User | None = None) -> None:
        """Flush all accumulated operations to the database."""


class LocationHandler:

    """
    Facade used by importers. Delegates to the appropriate BaseLocationManager
    implementation based on V3_FEATURE_LOCATIONS.

    Callers only see the methods defined here — they cannot reach into the
    internal manager to call implementation-specific methods. This prevents
    V3-only or endpoint-only code from leaking into shared importer logic.
    """

    def __init__(
        self,
        product: Product,
        *,
        v3_manager_class: type[BaseLocationManager] | None = None,
        v2_manager_class: type[BaseLocationManager] | None = None,
    ) -> None:
        from django.conf import settings  # noqa: PLC0415

        from dojo.importers.endpoint_manager import EndpointManager  # noqa: PLC0415
        from dojo.importers.location_manager import LocationManager  # noqa: PLC0415

        self._product = product
        if settings.V3_FEATURE_LOCATIONS:
            cls = v3_manager_class or LocationManager
        else:
            cls = v2_manager_class or EndpointManager
        self._manager: BaseLocationManager = cls(product)

    # --- Delegates (one per BaseLocationManager method) ---

    def clean_unsaved(self, finding: Finding) -> None:
        return self._manager.clean_unsaved(finding)

    def record_for_finding(self, finding: Finding, extra_locations: list | None = None) -> None:
        return self._manager.record_for_finding(finding, extra_locations)

    def update_status(self, existing_finding: Finding, new_finding: Finding, user: Dojo_User) -> None:
        return self._manager.update_status(existing_finding, new_finding, user)

    def record_reactivations_for_finding(self, finding: Finding) -> None:
        return self._manager.record_reactivations_for_finding(finding)

    def record_mitigations_for_finding(self, finding: Finding, user: Dojo_User | None = None) -> None:
        return self._manager.record_mitigations_for_finding(finding, user)

    def get_locations_for_tagging(self, findings: list[Finding]):
        return self._manager.get_locations_for_tagging(findings)

    def get_location_tag_fallback(self, finding: Finding):
        return self._manager.get_location_tag_fallback(finding)

    def serialize_extra_locations(self, locations: list) -> dict:
        return self._manager.serialize_extra_locations(locations)

    def persist(self, user: Dojo_User | None = None) -> None:
        return self._manager.persist(user)
