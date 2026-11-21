from django.db.models import QuerySet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet

from dojo.api_v2.views import PrefetchDojoModelViewSet
from dojo.authorization.api_permissions import (
    LocationFindingReferencePermission,
    LocationProductReferencePermission,
)
from dojo.location.api.filters import (
    LocationFilter,
    LocationFindingReferenceFilter,
    LocationProductReferenceFilter,
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
    get_authorized_locations,
    mark_tags_readable,
)


class LocationViewSet(ReadOnlyModelViewSet):

    """A simple ViewSet for viewing and editing Locations."""

    serializer_class = LocationSerializer
    queryset = Location.objects.none()
    filterset_class = LocationFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = [IsAuthenticated]

    def get_queryset(self) -> QuerySet[Location]:
        """Return the queryset of Locations the requesting user may view."""
        queryset = get_authorized_locations("view", Location.objects.order_by_id())
        return queryset.prefetch_related("tags", "inherited_tags")

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        # Tag readability is resolved for the page's rows after the page is fetched. As an
        # annotation it rode along in the pagination COUNT and ran for every row before OFFSET.
        serializer = self.get_serializer(mark_tags_readable(queryset if page is None else page), many=True)
        if page is None:
            return Response(serializer.data)
        return self.get_paginated_response(serializer.data)


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
        return get_authorized_location_finding_reference("view").select_related("location")


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
        return get_authorized_location_product_reference("view").select_related("location")
