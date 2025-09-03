from django.db.models import QuerySet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import DjangoModelPermissions
from rest_framework.viewsets import ModelViewSet

from dojo.api_v2.permissions import IsSuperUser
from dojo.url.api.filters import URLFilter
from dojo.url.api.serializer import URLSerializer
from dojo.url.models import URL


class URLViewSet(ModelViewSet):

    """A simple ViewSet for viewing and editing Locations."""

    serializer_class = URLSerializer
    queryset = URL.objects.none()
    filterset_class = URLFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = (IsSuperUser, DjangoModelPermissions)

    def get_queryset(self) -> QuerySet[URL]:
        """Return the queryset of Vulnerabilities."""
        return URL.objects.all()
