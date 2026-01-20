from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

import dojo.api_v2.mixins as dojo_mixins
from dojo.api_v2 import permissions, prefetch
from dojo.api_v2.serializers import ReportGenerateOptionSerializer, ReportGenerateSerializer
from dojo.api_v2.views import PrefetchDojoModelViewSet, report_generate, schema_with_prefetch
from dojo.asset.api import serializers
from dojo.asset.api.filters import (
    ApiAssetFilter,
    AssetAPIScanConfigurationFilterSet,
    AssetGroupFilterSet,
    AssetMemberFilterSet,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
)
from dojo.product.queries import (
    get_authorized_product_api_scan_configurations,
    get_authorized_product_groups,
    get_authorized_product_members,
    get_authorized_products,
)
from dojo.utils import async_delete, get_setting


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class AssetAPIScanConfigurationViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.AssetAPIScanConfigurationSerializer
    queryset = Product_API_Scan_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = AssetAPIScanConfigurationFilterSet
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasAssetAPIScanConfigurationPermission,
    )

    def get_queryset(self):
        return get_authorized_product_api_scan_configurations(
            Permissions.Product_API_Scan_Configuration_View,
        )


@extend_schema_view(**schema_with_prefetch())
class AssetViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
    dojo_mixins.DeletePreviewModelMixin,
):
    serializer_class = serializers.AssetSerializer
    queryset = Product.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiAssetFilter
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasAssetPermission,
    )

    def get_queryset(self):
        return get_authorized_products(Permissions.Product_View).distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # def list(self, request):
    #     # Note the use of `get_queryset()` instead of `self.queryset`
    #     queryset = self.get_queryset()
    #     serializer = self.serializer_class(queryset, many=True)
    #     return Response(serializer.data)

    @extend_schema(
        request=ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        product = self.get_object()

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

        data = report_generate(request, product, options)
        report = ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class AssetMemberViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.AssetMemberSerializer
    queryset = Product_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = AssetMemberFilterSet
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasAssetMemberPermission,
    )

    def get_queryset(self):
        return get_authorized_product_members(
            Permissions.Product_View,
        ).distinct()

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class AssetGroupViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.AssetGroupSerializer
    queryset = Product_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = AssetGroupFilterSet
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasAssetGroupPermission,
    )

    def get_queryset(self):
        return get_authorized_product_groups(
            Permissions.Product_Group_View,
        ).distinct()

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)
