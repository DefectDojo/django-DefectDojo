import logging
from dojo.api_v2.utils import http_response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.cache import cache
from dojo.api_v2.manager_cache.serializers import ManagerCacheSerializers
from dojo.api_v2.api_error import ApiError
from drf_spectacular.utils import (
    extend_schema,
)
from dojo.api_v2 import (
    permissions,
)
logger = logging.getLogger(__name__)


class ManagerCacheApiView(
    APIView
        ):
    permission_classes = (IsAuthenticated,
                          permissions.UserHasPermissionManagerCache,)

    @extend_schema(
        request=ManagerCacheSerializers,
        responses={status.HTTP_201_CREATED: ManagerCacheSerializers},
    )
    def get(self, request):
        serializer = ManagerCacheSerializers(data=request.query_params)
        if serializer.is_valid():
            pattern = serializer.validated_data.get('pattern')
            redis_client = cache.client.get_client()
            keys = [key.decode('utf-8') for key in redis_client.scan_iter(pattern)]
        else:
            return http_response.bad_request(
                message="Invalid serializer", data=serializer.errors)
        return http_response.ok(message="List Key Cache", data=keys)

    def post(self, request):
        serializer = ManagerCacheSerializers(data=request.query_params)
        if serializer.is_valid():
            pattern = serializer.validated_data.get('pattern')
            redis_client = cache.client.get_client()
            for key in redis_client.scan_iter(pattern):
                redis_client.delete(key)
        else:
            return http_response.bad_request(
                message="Invalid serializer", data=serializer.errors)
        return http_response.ok(message="Deleted Key Cache", data="success")
