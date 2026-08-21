from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2.serializers import ReportGenerateOptionSerializer, ReportGenerateSerializer
from dojo.api_v2.views import PrefetchDojoModelViewSet, report_generate, schema_with_prefetch
from dojo.authorization import api_permissions as permissions
from dojo.models import Product_Type
from dojo.organization.api import serializers
from dojo.organization.api.filters import OrganizationFilterSet
from dojo.product_type.queries import get_authorized_product_types
from dojo.utils import async_delete, get_setting


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class OrganizationViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.OrganizationSerializer
    queryset = Product_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = OrganizationFilterSet
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasOrganizationPermission,
    )

    def get_queryset(self):
        return get_authorized_product_types(
            "view",
        ).distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        product_type = self.get_object()

        options = {}
        # prepare post data
        report_options = ReportGenerateOptionSerializer(
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

        data = report_generate(request, product_type, options)
        report = ReportGenerateSerializer(data)
        return Response(report.data)
