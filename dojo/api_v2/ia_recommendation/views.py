import logging
from dojo.api_v2.utils import http_response
from django.shortcuts import get_object_or_404
from dojo.models import Finding
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.cache import cache
from dojo.api_v2.ia_recommendation.serializers import IaRecommendationSerializer
from dojo.api_v2.ia_recommendation.helper import get_ia_recommendation
from dojo.api_v2.api_error import ApiError
from drf_spectacular.utils import (
    extend_schema,
)
from dojo.api_v2 import (
    permissions,
)
logger = logging.getLogger(__name__)


class IArecommendationApiView(APIView):
    permission_classes = (IsAuthenticated,
                          permissions.UserHasFindingPermission,)
    serializer_class = IaRecommendationSerializer

    @extend_schema(
        responses={status.HTTP_200_OK: IaRecommendationSerializer},
    )
    def get(self, request, id):
        finding = get_object_or_404(Finding, pk=id)
        ia_recommendation = get_ia_recommendation(str(finding.id), request.user)
        return ia_recommendation
