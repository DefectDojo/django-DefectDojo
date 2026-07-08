import logging

from django.db.models import OuterRef, Value
from django.db.models.functions import Coalesce
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2 import serializers as api_v2_serializers
from dojo.api_v2.views import PrefetchDojoModelViewSet, report_generate
from dojo.authorization import api_permissions as permissions
from dojo.endpoint.api.filters import ApiEndpointFilter
from dojo.endpoint.api.serializer import (
    EndpointMetaImporterSerializer,
    EndpointSerializer,
    EndpointStatusSerializer,
)
from dojo.endpoint.models import Endpoint, Endpoint_Status
from dojo.endpoint.queries import (
    get_authorized_endpoint_status,
    get_authorized_endpoints,
)
from dojo.models import Finding
from dojo.product.queries import get_authorized_products
from dojo.query_utils import build_count_subquery

logger = logging.getLogger(__name__)


# Authorization: authenticated users
# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class EndPointViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = EndpointSerializer
    queryset = Endpoint.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiEndpointFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEndpointPermission,
    )

    def get_queryset(self):
        active_finding_subquery = build_count_subquery(
            Finding.objects.filter(endpoints=OuterRef("pk"), active=True),
            group_field="endpoints",
        )
        return get_authorized_endpoints("view").annotate(
            active_finding_count=Coalesce(active_finding_subquery, Value(0)),
        ).distinct()

    @extend_schema(
        request=api_v2_serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: api_v2_serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"],
        # IsAuthenticated only: report generation requires View permission,
        # enforced by the permission-filtered get_queryset(). The viewset's
        # permission_classes would check Edit (POST), which is too restrictive.
        permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        endpoint = self.get_object()

        options = {}
        # prepare post data
        report_options = api_v2_serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, endpoint, options)
        report = api_v2_serializers.ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class EndpointStatusViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = EndpointStatusSerializer
    queryset = Endpoint_Status.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "mitigated",
        "false_positive",
        "out_of_scope",
        "risk_accepted",
        "mitigated_by",
        "finding",
        "endpoint",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEndpointStatusPermission,
    )

    def get_queryset(self):
        return get_authorized_endpoint_status(
            "view",
        ).distinct()


# Authorization: authenticated users, DjangoModelPermissions
class EndpointMetaImporterView(
    mixins.CreateModelMixin, viewsets.GenericViewSet,
):

    """
    Imports a CSV file into a product to propagate arbitrary meta and tags on endpoints.

    By Names:
    - Provide `product_name` of existing product

    By ID:
    - Provide the id of the product in the `product` parameter

    In this scenario Defect Dojo will look up the product by the provided details.
    """

    serializer_class = EndpointMetaImporterSerializer
    parser_classes = [MultiPartParser]
    queryset = Finding.objects.none()
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasMetaImportPermission,
    )

    def perform_create(self, serializer):
        serializer.save()

    def get_queryset(self):
        return get_authorized_products("edit")
