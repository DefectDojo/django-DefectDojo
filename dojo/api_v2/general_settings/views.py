import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db import transaction, IntegrityError
from dojo.models import GeneralSettings
from dojo.api_v2.general_settings.serializers import GeneralSettingsSerializers
from dojo.api_v2.views import DojoModelViewSet
from dojo.api_v2.utils import http_response
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
    
    @extend_schema(
        request=GeneralSettingsSerializers,
        responses={status.HTTP_201_CREATED: GeneralSettingsSerializers},
    )
    def create(self, request, *args, **kwargs):
        """
        Create a new GeneralSettings object.
        """
        try:
            if isinstance(request.data, list):
                serializer = GeneralSettingsSerializers(data=request.data,
                                                        many=True)
                if serializer.is_valid():
                    variables = []
                    for variable in serializer.validated_data:
                        variables.append(GeneralSettings(**variable))
                    with transaction.atomic():
                        GeneralSettings.objects.bulk_create(variables)
                        http_response.created(
                            message="GeneralSettings created",
                            data=serializer.validated_data)
                else:
                    return http_response.bad_request(
                        data=serializer.errors, message="Invalid data")
            else:
                return super().create(request, *args, **kwargs)

        except IntegrityError as e:
            raise ApiError.unique_constraint_error(detail=str(e), field_name="name_key")
        except Exception as e:
            logger.error(str(e))
            raise ApiError.internal_server_error(detail=str(e))
