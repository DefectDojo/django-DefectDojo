from rest_framework import mixins, status, viewsets
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from django.shortcuts import get_object_or_404
from dojo.models import GeneralSettings
from dojo.api_v2 import (
    permissions,
    prefetch,
    serializers,
)
from dojo.api_v2.general_settings.serializers import GeneralSettingsSerializers
from dojo.api_v2.views import DojoModelViewSet, schema_with_prefetch
from dojo.api_v2.utils import http_response
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    OpenApiTypes,
)

@extend_schema_view(**schema_with_prefetch())
class GeneralSettingsViewSet(prefetch.PrefetchListMixin,
                             prefetch.PrefetchRetrieveMixin,
                             DojoModelViewSet):
    queryset = GeneralSettings.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = GeneralSettingsSerializers
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name_key",
        "value",
        "category",
        "status",
        "updated",
        "created"]