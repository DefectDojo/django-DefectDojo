"""
Compatibility viewsets and serializers for Endpoint API using new Location models.

These viewsets maintain API compatibility with the legacy Endpoint and Endpoint_Status
models while using the new URL and LocationFindingReference models underneath.
"""
import datetime

from django_filters import BooleanFilter, CharFilter, NumberFilter
from django_filters.rest_framework import DjangoFilterBackend, FilterSet
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.fields import (
    CharField,
    DateTimeField,
    IntegerField,
    SerializerMethodField,
)
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import ModelSerializer
from rest_framework.viewsets import ReadOnlyModelViewSet

from dojo.api_v2 import serializers
from dojo.api_v2.permissions import check_object_permission
from dojo.api_v2.prefetch import PrefetchListMixin, PrefetchRetrieveMixin
from dojo.api_v2.serializers import TagListSerializerField
from dojo.api_v2.views import report_generate
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import CharFieldFilterANDExpression, CharFieldInFilter, OrderingFilter
from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.location.queries import get_authorized_location_finding_reference, get_authorized_location_product_reference
from dojo.location.status import FindingLocationStatus
from dojo.url.models import URL

##########
# Common
##########


class V2WritesDisabled(BasePermission):

    """Disallows non-safe HTTP methods."""

    message = "Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled"

    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS

    def has_object_permission(self, request, view, obj):
        return request.method in permissions.SAFE_METHODS


class UserHasLocationRefPermission(BasePermission):

    """Permission class for Location(Product|Finding)Reference model access."""

    def has_object_permission(self, request, view, obj):
        # obj is a URL instance, check permission on its location
        return check_object_permission(
            request,
            obj,
            Permissions.Location_View,
            Permissions.Location_Edit,
            Permissions.Location_Delete,
        )


##########
# Endpoint compatibility
##########

class V3EndpointCompatibleFilterSet(FilterSet):

    """Endpoint-compatible FilterSet."""

    id = NumberFilter(field_name="id", lookup_expr="exact")

    protocol = CharFilter(field_name="location__url__protocol", lookup_expr="icontains")
    userinfo = CharFilter(field_name="location__url__user_info", lookup_expr="icontains")
    host = CharFilter(field_name="location__url__host", lookup_expr="icontains")
    port = NumberFilter(field_name="location__url__port", lookup_expr="exact")
    path = CharFilter(field_name="location__url__path", lookup_expr="icontains")
    query = CharFilter(field_name="location__url__query", lookup_expr="icontains")
    fragment = CharFilter(field_name="location__url__fragment", lookup_expr="icontains")

    product = NumberFilter(field_name="product__id", lookup_expr="exact")

    location_id = NumberFilter(field_name="location__id", lookup_expr="exact")

    tag = CharFilter(field_name="location__tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(field_name="location__tags__name", lookup_expr="in", help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(field_name="location__tags__name", help_text="Comma separated list of exact tags to match with an AND expression")
    not_tag = CharFilter(field_name="location__tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude=True)
    not_tags = CharFieldInFilter(field_name="location__tags__name", lookup_expr="in", help_text="Comma separated list of exact tags not present on model", exclude=True)
    has_tags = BooleanFilter(field_name="location__tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        fields=(
            ("location__url__host", "host"),
            ("product__id", "product"),
            ("id", "id"),
        ),
    )


class V3EndpointCompatibleSerializer(ModelSerializer):

    """Serializes a LocationProductReference model to something that looks like an Endpoint."""

    protocol = CharField(source="location.url.protocol")
    userinfo = CharField(source="location.url.user_info")
    host = CharField(source="location.url.host")
    port = IntegerField(source="location.url.port")
    path = CharField(source="location.url.path")
    query = CharField(source="location.url.query")
    fragment = CharField(source="location.url.fragment")
    tags = TagListSerializerField(source="location.tags")
    location_id = IntegerField(source="location.id")

    class Meta:
        model = LocationProductReference
        exclude = ("location",)


class V3EndpointCompatibleViewSet(PrefetchListMixin, PrefetchRetrieveMixin, viewsets.ReadOnlyModelViewSet):

    """Read-only ViewSet for LocationProductReferences that behaves similar to EndpointViewSet for reads."""

    serializer_class = V3EndpointCompatibleSerializer
    queryset = LocationProductReference.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = V3EndpointCompatibleFilterSet

    permission_classes = (
        IsAuthenticated,
        V2WritesDisabled,
        UserHasLocationRefPermission,
    )

    def get_queryset(self):
        """Get authorized URLs using Endpoint authorization logic."""
        return get_authorized_location_product_reference(Permissions.Location_View).filter(location__location_type=URL.LOCATION_TYPE).distinct()

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"], permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        endpoint = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(
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
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)


##########
# Endpoint_Status-compatibility
##########

class V3EndpointStatusCompatibleFilterSet(FilterSet):

    """Endpoint_Status-compatible FilterSet."""

    mitigated = BooleanFilter(method="filter_mitigated")
    false_positive = BooleanFilter(method="filter_false_positive")
    out_of_scope = BooleanFilter(method="filter_out_of_scope")
    risk_accepted = BooleanFilter(method="filter_risk_accepted")

    mitigated_by = CharFilter(method="filter_mitigated_by")

    finding = NumberFilter(field_name="finding", lookup_expr="exact")
    endpoint = NumberFilter(method="filter_endpoint")

    def filter_mitigated(self, queryset, name, value):
        if value:
            return queryset.filter(status=FindingLocationStatus.Mitigated)
        return queryset.exclude(status=FindingLocationStatus.Mitigated)

    def filter_false_positive(self, queryset, name, value):
        if value:
            return queryset.filter(status=FindingLocationStatus.FalsePositive)
        return queryset.exclude(status=FindingLocationStatus.FalsePositive)

    def filter_out_of_scope(self, queryset, name, value):
        if value:
            return queryset.filter(status=FindingLocationStatus.OutOfScope)
        return queryset.exclude(status=FindingLocationStatus.OutOfScope)

    def filter_risk_accepted(self, queryset, name, value):
        if value:
            return queryset.filter(status=FindingLocationStatus.RiskAccepted)
        return queryset.exclude(status=FindingLocationStatus.RiskAccepted)

    def filter_mitigated_by(self, queryset, name, value):
        return queryset.filter(status=FindingLocationStatus.Mitigated, auditor__iexact=value)

    def filter_endpoint(self, queryset, name, value):
        return queryset.filter(location__products__id=value)

    class Meta:
        model = LocationFindingReference
        fields = ["mitigated", "false_positive", "out_of_scope", "risk_accepted", "mitigated_by", "finding", "endpoint"]


class V3EndpointStatusCompatibleSerializer(ModelSerializer):

    """Serializes a LocationFindingReference model to something that looks like an Endpoint_Status."""

    date = SerializerMethodField()
    last_modified = DateTimeField(source="updated")

    mitigated = SerializerMethodField()
    mitigated_time = SerializerMethodField()
    mitigated_by = SerializerMethodField()
    false_positive = SerializerMethodField()
    out_of_scope = SerializerMethodField()
    risk_accepted = SerializerMethodField()

    endpoint = SerializerMethodField()
    location_id = IntegerField(source="location.id")

    def get_date(self, obj) -> datetime.date | None:
        return obj.created.date() if obj.created else None

    def get_mitigated(self, obj) -> bool | None:
        return obj.created.date() if obj.created else None

    def get_mitigated_time(self, obj) -> datetime.datetime | None:
        return obj.audit_time if self.get_mitigated(obj) else None

    def get_mitigated_by(self, obj) -> int | None:
        return obj.auditor.id if self.get_mitigated(obj) and obj.auditor else None

    def get_false_positive(self, obj) -> bool | None:
        return obj.status == FindingLocationStatus.FalsePositive

    def get_out_of_scope(self, obj) -> bool | None:
        return obj.status == FindingLocationStatus.OutOfScope

    def get_risk_accepted(self, obj) -> bool | None:
        return obj.status == FindingLocationStatus.RiskAccepted

    def get_endpoint(self, obj) -> int | None:
        product_ref = LocationProductReference.objects.filter(
            location=obj.location,
            product=obj.finding.test.engagement.product,
        ).first()
        return product_ref.location.id if product_ref else None

    class Meta:
        model = LocationFindingReference
        exclude = ("location",)


class V3EndpointStatusCompatibleViewSet(PrefetchListMixin, PrefetchRetrieveMixin, ReadOnlyModelViewSet):

    """Read-only ViewSet for LocationFindingReferences that behaves similar to EndpointViewSet for reads."""

    serializer_class = V3EndpointStatusCompatibleSerializer
    queryset = LocationFindingReference.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = V3EndpointStatusCompatibleFilterSet

    permission_classes = (
        IsAuthenticated,
        V2WritesDisabled,
        UserHasLocationRefPermission,
    )

    def get_queryset(self):
        """Get authorized URLs using Endpoint authorization logic."""
        return get_authorized_location_finding_reference(Permissions.Location_View).filter(location__location_type=URL.LOCATION_TYPE).distinct()
