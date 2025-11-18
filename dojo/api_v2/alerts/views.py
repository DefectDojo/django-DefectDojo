import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db import transaction, IntegrityError
from dojo.models import Alerts 
from dojo.api_v2.alerts.serializers import AlertsSerializers
from dojo.api_v2.views import DojoModelViewSet
from dojo.api_v2.utils import http_response
from dojo.authorization.roles_permissions import Permissions
from django_filters.rest_framework import DjangoFilterBackend
from dojo.api_v2.api_error import ApiError
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    OpenApiTypes,
)
from dojo.api_v2 import (
    permissions,
    prefetch,
    serializers,
)
logger = logging.getLogger(__name__)

@extend_schema_view(
    list=extend_schema(
        responses={status.HTTP_200_OK: AlertsSerializers(many=True)},
    ),
    create=extend_schema(
        request=AlertsSerializers,
        responses={status.HTTP_201_CREATED: AlertsSerializers},
    ),
)
class AlertViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    DojoModelViewSet
):
    queryset = Alerts.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = AlertsSerializers
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "source",
        "created"]
    
    def get_queryset(self):
        return Alerts.objects.filter(user_id=self.request.user.id)

    def list(self, request, *args, **kwargs):
        """
        List all Alerts objects.
        """
        try:
            alerts_qr = self.get_queryset()
            page = self.paginate_queryset(alerts_qr)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            serializer = self.get_serializer(alerts_qr, many=True)
            return http_response.ok(data=serializer.data)

        except Exception as e:
            logger.error(str(e))
            raise ApiError.internal_server_error(detail=str(e))
