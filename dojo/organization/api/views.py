from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2 import permissions
from dojo.api_v2.serializers import ReportGenerateOptionSerializer, ReportGenerateSerializer
from dojo.api_v2.views import PrefetchDojoModelViewSet, report_generate, schema_with_prefetch
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
    Role,
)
from dojo.organization.api import serializers
from dojo.organization.api.filters import (
    OrganizationFilterSet,
    OrganizationGroupFilterSet,
    OrganizationMemberFilterSet,
)
from dojo.product_type.queries import (
    get_authorized_product_type_groups,
    get_authorized_product_type_members,
    get_authorized_product_types,
)
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
            Permissions.Product_Type_View,
        ).distinct()

    # Overwrite perfom_create of CreateModelMixin to add current user as owner
    def perform_create(self, serializer):
        serializer.save()
        product_type_data = serializer.data
        product_type_data.pop("authorization_groups")
        product_type_data.pop("members")
        # Manage custom fields separately with default fields of false
        product_type_data["critical_product"] = product_type_data.pop("critical_asset", False)
        product_type_data["key_product"] = product_type_data.pop("key_asset", False)
        member = Product_Type_Member()
        member.user = self.request.user
        member.product_type = Product_Type(**product_type_data)
        member.role = Role.objects.get(is_owner=True)
        member.save()

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


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class OrganizationMemberViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.OrganizationMemberSerializer
    queryset = Product_Type_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = OrganizationMemberFilterSet
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasOrganizationMemberPermission,
    )

    def get_queryset(self):
        return get_authorized_product_type_members(
            Permissions.Product_Type_View,
        ).distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role.is_owner:
            owners = Product_Type_Member.objects.filter(
                product_type=instance.product_type, role__is_owner=True,
            ).count()
            if owners <= 1:
                return Response(
                    "There must be at least one owner",
                    status=status.HTTP_400_BAD_REQUEST,
                )
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class OrganizationGroupViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.OrganizationGroupSerializer
    queryset = Product_Type_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = OrganizationGroupFilterSet
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasOrganizationGroupPermission,
    )

    def get_queryset(self):
        return get_authorized_product_type_groups(
            Permissions.Product_Type_Group_View,
        ).distinct()

    @extend_schema(
        exclude=True,
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {"message": "Patch function is not offered in this path."}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)
