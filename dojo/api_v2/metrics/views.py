import logging
from dojo.api_v2.utils import http_response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.cache import cache
from dojo.api_v2.metrics.serializers import MetricsIARecommendationSerializers
from dojo.api_v2.api_error import ApiError
from dojo.api_v2.metrics.helper import add_ratings
from dojo.models import Finding
from drf_spectacular.utils import (
    extend_schema,
)
from dojo.api_v2 import (
    permissions,
)
logger = logging.getLogger(__name__)


class MetricIARecommendationApiView(
    APIView
        ):
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasPermissionMetrics,)
    serializer_class = MetricsIARecommendationSerializers 

    @extend_schema(
        request=MetricsIARecommendationSerializers,
        responses={status.HTTP_201_CREATED: MetricsIARecommendationSerializers},
    )
    def get(self, request):
        serializer = MetricsIARecommendationSerializers(
            data=request.query_params)
        if serializer.is_valid():
            data = {
                "iteration_counter": 0,
                "like_counter": 0,
                "dislike_counter": 0,
                "users": {}
            }
            findings_queyset = Finding.objects.filter(
                ia_recommendation__isnull=False)
            for finding in findings_queyset:
                data = add_ratings(data, finding, request.user)
            return http_response.ok(
                message="Metrics IA Recommendation",
                data=data)
        else:
            return http_response.bad_request(
                message="Invalid serializer", data=serializer.errors)

