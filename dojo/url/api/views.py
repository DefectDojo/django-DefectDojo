from django.db.models import QuerySet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import DjangoModelPermissions

from dojo.api_v2.permissions import IsSuperUser
from dojo.api_v2.views import PrefetchDojoModelViewSet
from dojo.url.api.filters import URLFilter
from dojo.url.api.serializer import URLSerializer
from dojo.url.models import URL


class URLViewSet(PrefetchDojoModelViewSet):

    """A simple ViewSet for viewing and editing Locations."""

    serializer_class = URLSerializer
    queryset = URL.objects.none()
    filterset_class = URLFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = (IsSuperUser, DjangoModelPermissions)
    lookup_field = "location_id"
    lookup_url_kwarg = "pk"

    def get_queryset(self) -> QuerySet[URL]:
        """Return the queryset of Vulnerabilities."""
        return URL.objects.all()
