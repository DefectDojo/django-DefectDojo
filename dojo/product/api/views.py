from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

import dojo.api_v2.mixins as dojo_mixins
from dojo.api_v2 import prefetch
from dojo.api_v2 import serializers as api_v2_serializers
from dojo.api_v2.views import PrefetchDojoModelViewSet, report_generate, schema_with_prefetch
from dojo.authorization import api_permissions as permissions
from dojo.models import Endpoint, Product, Product_API_Scan_Configuration
from dojo.product.api.filters import ApiProductFilter
from dojo.product.api.serializer import (
    ProductAPIScanConfigurationSerializer,
    ProductSerializer,
)
from dojo.product.queries import (
    get_authorized_product_api_scan_configurations,
    get_authorized_products,
)
from dojo.utils import async_delete, get_setting


# Authorization: object-based
class ProductAPIScanConfigurationViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = ProductAPIScanConfigurationSerializer
    queryset = Product_API_Scan_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "product",
        "tool_configuration",
        "service_key_1",
        "service_key_2",
        "service_key_3",
    ]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductAPIScanConfigurationPermission,
    )

    def get_queryset(self):
        return get_authorized_product_api_scan_configurations(
            "view",
        )


@extend_schema_view(**schema_with_prefetch())
class ProductViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
    dojo_mixins.DeletePreviewModelMixin,
):
    serializer_class = ProductSerializer
    queryset = Product.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiProductFilter
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasProductPermission,
    )

    def get_queryset(self):
        return get_authorized_products("view").distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            with Endpoint.allow_endpoint_init():  # TODO: Delete this after the move to Locations
                instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # def list(self, request):
    #     # Note the use of `get_queryset()` instead of `self.queryset`
    #     queryset = self.get_queryset()
    #     serializer = self.serializer_class(queryset, many=True)
    #     return Response(serializer.data)

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
        product = self.get_object()

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

        data = report_generate(request, product, options)
        report = api_v2_serializers.ReportGenerateSerializer(data)
        return Response(report.data)
