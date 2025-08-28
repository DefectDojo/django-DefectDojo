from django.db.models import QuerySet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet

from dojo.api_v2.permissions import IsSuperUser
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


class LocationViewSet(ReadOnlyModelViewSet):

    """A simple ViewSet for viewing and editing Locations."""

    serializer_class = LocationSerializer
    queryset = Location.objects.none()
    filterset_class = LocationFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = (IsSuperUser, DjangoModelPermissions)

    def get_queryset(self) -> QuerySet[Location]:
        """Return the queryset of Vulnerabilities."""
        return Location.objects.all()


class LocationFindingReferenceViewSet(ModelViewSet):

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
        """Return the queryset of Vulnerabilities."""
        return LocationFindingReference.objects.all()


class LocationProductReferenceViewSet(ModelViewSet):

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
        """Return the queryset of Vulnerabilities."""
        return LocationProductReference.objects.all()
