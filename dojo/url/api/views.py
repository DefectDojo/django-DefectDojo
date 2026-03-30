from django.db.models import OuterRef, QuerySet, Value
from django.db.models.functions import Coalesce
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import DjangoModelPermissions

from dojo.api_v2.permissions import IsSuperUser
from dojo.api_v2.views import PrefetchDojoModelViewSet
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.query_utils import build_count_subquery
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
        active_finding_subquery = build_count_subquery(
            LocationFindingReference.objects.filter(
                location__url=OuterRef("pk"),
                status=FindingLocationStatus.Active,
            ),
            group_field="location__url",
        )
        return URL.objects.annotate(
            active_findings=Coalesce(active_finding_subquery, Value(0)),
        )

    def perform_destroy(self, instance):
        instance.location.delete()
