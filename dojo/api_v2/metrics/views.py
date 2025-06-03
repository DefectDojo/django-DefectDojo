import logging
from collections import OrderedDict
from rest_framework.generics import GenericAPIView
from dojo.api_v2.utils import http_response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import LimitOffsetPagination
from django.core.cache import cache
from dojo.api_v2.metrics.serializers import MetricsIARecommendationSerializers
from dojo.api_v2.api_error import ApiError
from dojo.api_v2.metrics.helper import get_metrics_ia_recommendation
from dojo.models import Finding
from drf_spectacular.utils import (
    extend_schema,
)
from dojo.api_v2 import (
    permissions,
)
logger = logging.getLogger(__name__)


class MetricIARecommendationApiView(
    GenericAPIView
        ):
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasPermissionMetrics,)
    serializer_class = MetricsIARecommendationSerializers 
    pagination_class = LimitOffsetPagination

    @extend_schema(
        request=MetricsIARecommendationSerializers,
        responses={status.HTTP_201_CREATED: MetricsIARecommendationSerializers},
    )
    def get(self, request):
        serializer = MetricsIARecommendationSerializers(
            data=request.query_params)
        if serializer.is_valid():
            data = {
                "interaction_counter": 0,
                "like_counter": 0,
                "dislike_counter": 0,
                "users": {}
            }
            findings_queyset = Finding.objects.filter(
                ia_recommendation__isnull=False)
            for finding in findings_queyset:
                data = get_metrics_ia_recommendation(data,
                                   finding,
                                   exclude_field=serializer.validated_data.get("exclude_field", []))

            users_data = [{"username":user, **user_data} for user, user_data in data["users"].items()]
            # Apply pagination
            paginator = self.pagination_class()
            paginated_data = paginator.paginate_queryset(users_data, request)

            # build the response data
            paginated_response = OrderedDict({
                "interaction_counter": data["interaction_counter"],
                "like_counter": data["like_counter"],
                "dislike_counter": data["dislike_counter"],
                "users": paginated_data
            })

            return paginator.get_paginated_response(paginated_response)
            # return http_response.ok(
            #     message="Metrics IA Recommendation",
            #     data=data)
        else:
            return http_response.bad_request(
                message="Invalid serializer", data=serializer.errors)
