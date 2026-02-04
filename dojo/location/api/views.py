from django.db.models import QuerySet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.viewsets import ReadOnlyModelViewSet

from dojo.api_v2.permissions import IsSuperUser
from dojo.api_v2.views import PrefetchDojoModelViewSet
from dojo.authorization.roles_permissions import Permissions
from dojo.location.api.filters import (
    LocationFilter,
    LocationFindingReferenceFilter,
    LocationProductReferenceFilter,
)
from dojo.location.api.permissions import (
    LocationFindingReferencePermission,
    LocationProductReferencePermission,
)
from dojo.location.api.serializers import (
    LocationFindingReferenceSerializer,
    LocationProductReferenceSerializer,
    LocationSerializer,
)
from dojo.location.models import (
    Location,
    LocationFindingReference,
    LocationProductReference,
)
from dojo.location.queries import (
    get_authorized_location_finding_reference,
    get_authorized_location_product_reference,
)


class LocationViewSet(ReadOnlyModelViewSet):

    """A simple ViewSet for viewing and editing Locations."""

    serializer_class = LocationSerializer
    queryset = Location.objects.none()
    filterset_class = LocationFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = (IsSuperUser, DjangoModelPermissions)

    def get_queryset(self) -> QuerySet[Location]:
        """Return the queryset of Locations."""
        return Location.objects.order_by_id()


class LocationFindingReferenceViewSet(PrefetchDojoModelViewSet):

    """A simple ViewSet for viewing and editing LocationFindingReference."""

    serializer_class = LocationFindingReferenceSerializer
    queryset = LocationFindingReference.objects.none()
    filterset_class = LocationFindingReferenceFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = [
        IsAuthenticated,
        LocationFindingReferencePermission,
    ]

    def get_queryset(self) -> QuerySet[LocationFindingReference]:
        """Return the queryset of LocationFindingReferences."""
        return get_authorized_location_finding_reference(Permissions.Location_View)


class LocationProductReferenceViewSet(PrefetchDojoModelViewSet):

    """A simple ViewSet for viewing and editing LocationProductReference."""

    serializer_class = LocationProductReferenceSerializer
    queryset = LocationProductReference.objects.none()
    filterset_class = LocationProductReferenceFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = [
        IsAuthenticated,
        LocationProductReferencePermission,
    ]

    def get_queryset(self) -> QuerySet[LocationProductReference]:
        """Return the queryset of LocationProductReferences."""
        return get_authorized_location_product_reference(Permissions.Location_View)
