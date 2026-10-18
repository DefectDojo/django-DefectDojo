"""
Compatibility viewsets and serializers for Endpoint API using new Location models.

These viewsets maintain API compatibility with the legacy Endpoint and Endpoint_Status
models while using the new URL and LocationFindingReference models underneath. Reads
project Location rows into the legacy shapes; writes go through dojo.location.services,
which maps each legacy write onto the Location rows it stands for.
"""
import datetime

import pghistory
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import OuterRef, Prefetch, Subquery, Value
from django.db.models.functions import Coalesce
from django.shortcuts import get_object_or_404
from django_filters import BooleanFilter, CharFilter, NumberFilter
from django_filters.rest_framework import DjangoFilterBackend, FilterSet
from drf_spectacular.utils import extend_schema
from rest_framework import serializers as drf_serializers
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ParseError
from rest_framework.fields import (
    BooleanField,
    CharField,
    DateField,
    DateTimeField,
    IntegerField,
    SerializerMethodField,
)
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.relations import PKOnlyObject, PrimaryKeyRelatedField
from rest_framework.response import Response
from rest_framework.serializers import ModelSerializer

from dojo.api_v2 import serializers
from dojo.api_v2.views import PrefetchDojoModelViewSet, report_generate
from dojo.authorization.api_permissions import (
    check_object_permission,
    check_post_permission,
    check_update_permission,
)
from dojo.filters import OrderingFilter
from dojo.location import services
from dojo.location.api.tag_filters import (
    ReadableHasTagsFilter,
    ReadableTagANDFilter,
    ReadableTagFilter,
    ReadableTagInFilter,
)
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.queries import (
    annotate_tags_readable,
    authorized_finding_references,
    get_authorized_location_finding_reference,
    get_authorized_location_product_reference,
)
from dojo.location.status import FindingLocationStatus
from dojo.models import Dojo_User, Finding, Product
from dojo.query_utils import build_count_subquery
from dojo.url.models import URL

##########
# Common
##########

# Every write through these routes carries this pghistory source, so the audit trail tells a
# legacy Endpoint API write apart from an import or a UI edit of the same Location.
PGHISTORY_SOURCE = "endpoint_api_compat"


def _validation_error(error: DjangoValidationError) -> drf_serializers.ValidationError:
    return drf_serializers.ValidationError(error.messages)


##########
# Endpoint compatibility
##########

# Rows here are LocationProductReference, so tag lookups resolve against location_id.
_LOCATION = "location_id"


class UserHasEndpointCompatPermission(BasePermission):

    """
    The legacy Endpoint permission, on LocationProductReference rows.

    Creating an endpoint needs add on its product. Reading, editing and deleting one need
    view, edit and delete on the reference's product: the authorization layer resolves
    products, not these join rows.
    """

    def has_permission(self, request, view):
        return check_post_permission(request, Product, "product", "add")

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            "view",
            "edit",
            "delete",
        ) and check_update_permission(request, obj, "add", "product")


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

    tag = ReadableTagFilter(lookup_expr="icontains", location_field=_LOCATION, help_text="Tag name contains")
    tags = ReadableTagInFilter(location_field=_LOCATION, help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = ReadableTagANDFilter(location_field=_LOCATION, help_text="Comma separated list of exact tags to match with an AND expression")
    not_tag = ReadableTagFilter(lookup_expr="icontains", exclude=True, location_field=_LOCATION, help_text="Not Tag name contains")
    not_tags = ReadableTagInFilter(exclude=True, location_field=_LOCATION, help_text="Comma separated list of exact tags not present on model")
    has_tags = ReadableHasTagsFilter(location_field=_LOCATION, label="Has tags")

    o = OrderingFilter(
        fields=(
            ("location__url__host", "host"),
            ("product__id", "product"),
            ("id", "id"),
            ("active_finding_count", "active_finding_count"),
        ),
        field_labels={
            "active_finding_count": "Active Findings Count",
        },
    )


class _LocationTagsField(serializers.TagListSerializerField):

    """Accepts a tag list like the legacy Endpoint, and reads back only tags the caller may see."""

    def get_attribute(self, instance):
        return instance

    def to_representation(self, value):
        return sorted(tag.name for tag in value.location.readable_tags)


def _url_field(field_class, url_field, **kwargs):
    # Optional, like the legacy Endpoint's nullable columns. validate() requires the host.
    return field_class(source=f"location.url.{url_field}", required=False, allow_null=True, **kwargs)


class V3EndpointCompatibleSerializer(ModelSerializer):

    """Serializes a LocationProductReference model to something that looks like an Endpoint."""

    protocol = _url_field(CharField, "protocol", allow_blank=True)
    userinfo = _url_field(CharField, "user_info", allow_blank=True)
    host = _url_field(CharField, "host", allow_blank=True)
    port = _url_field(IntegerField, "port")
    path = _url_field(CharField, "path", allow_blank=True)
    query = _url_field(CharField, "query", allow_blank=True)
    fragment = _url_field(CharField, "fragment", allow_blank=True)
    tags = _LocationTagsField(required=False)
    location_id = IntegerField(source="location.id", read_only=True)
    active_finding_count = IntegerField(read_only=True)

    class Meta:
        model = LocationProductReference
        exclude = ("location",)
        read_only_fields = ("status", "relationship", "relationship_data")
        # Required on create and PUT, checked in validate() with the legacy message.
        extra_kwargs = {"product": {"required": False}}

    def validate(self, attrs):
        given = attrs.pop("location", {}).get("url", {})
        if self.instance is None or self.context["request"].method != "PATCH":
            product = attrs.get("product")
            if product is None:
                msg = "Product is required"
                raise drf_serializers.ValidationError(msg)
            values = {field: given.get(url_field) for field, url_field in services.ENDPOINT_URL_FIELDS.items()}
        else:
            product = attrs.get("product", self.instance.product)
            current = self.instance.location.url
            values = {field: given.get(url_field, getattr(current, url_field)) for field, url_field in services.ENDPOINT_URL_FIELDS.items()}
        if self.instance is not None and product != self.instance.product:
            msg = "Change of product is not possible"
            raise drf_serializers.ValidationError(msg)
        try:
            url = services.build_url(**values)
        except DjangoValidationError as error:
            raise _validation_error(error) from error
        duplicate = services.product_reference_for(product, url)
        if duplicate is not None and (self.instance is None or duplicate.pk != self.instance.pk):
            msg = "It appears as though an endpoint with this data already exists for this product."
            raise drf_serializers.ValidationError(msg, code="invalid")
        attrs["product"] = product
        attrs["url"] = url
        return attrs

    def create(self, validated_data):
        try:
            return services.create_product_reference(
                validated_data["product"],
                validated_data["url"],
                tags=validated_data.get("tags"),
                user=self.context["request"].user,
            )
        except DjangoValidationError as error:
            raise _validation_error(error) from error

    def update(self, instance, validated_data):
        url = validated_data["url"]
        try:
            # One transaction, so a refused tag write also takes back the address change.
            with transaction.atomic():
                if url.identity_hash != instance.location.url.identity_hash:
                    instance = services.move_product_reference(instance, url)
                if (tags := validated_data.get("tags")) is not None:
                    services.set_location_tags(instance.location, tags, self.context["request"].user)
        except DjangoValidationError as error:
            raise _validation_error(error) from error
        return instance


class _ReloadAfterWriteMixin:

    """Answer a write with the row as a read returns it, annotations included."""

    def _reload(self, serializer):
        reloaded = self.get_queryset().filter(pk=serializer.instance.pk).first()
        if reloaded is not None:
            serializer.instance = reloaded

    def perform_create(self, serializer):
        with pghistory.context(source=PGHISTORY_SOURCE):
            serializer.save()
        self._reload(serializer)

    def perform_update(self, serializer):
        with pghistory.context(source=PGHISTORY_SOURCE):
            serializer.save()
        self._reload(serializer)


class V3EndpointCompatibleViewSet(_ReloadAfterWriteMixin, PrefetchDojoModelViewSet):

    """ViewSet for LocationProductReferences that behaves like EndpointViewSet, reads and writes."""

    serializer_class = V3EndpointCompatibleSerializer
    queryset = LocationProductReference.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = V3EndpointCompatibleFilterSet

    permission_classes = (
        IsAuthenticated,
        UserHasEndpointCompatPermission,
    )

    def get_queryset(self):
        """Get authorized URLs using Endpoint authorization logic."""
        active_finding_subquery = build_count_subquery(
            authorized_finding_references(self.request.user).filter(
                location=OuterRef("location"),
                status=FindingLocationStatus.Active,
            ),
            group_field="location",
        )
        return get_authorized_location_product_reference("view").filter(
            location__location_type=URL.LOCATION_TYPE,
        ).annotate(
            active_finding_count=Coalesce(active_finding_subquery, Value(0)),
        ).prefetch_related(
            # No DISTINCT: nothing here repeats a row (location and URL are one-to-one, the
            # authorization and tag filters are semi-joins), and a DISTINCT made the pagination
            # count deduplicate every reference.
            # The serializer reads location, location.url and the location's readable tags per row.
            Prefetch(
                "location",
                queryset=annotate_tags_readable(Location.objects.select_related("url")).prefetch_related("tags"),
            ),
        )

    def perform_destroy(self, instance):
        with pghistory.context(source=PGHISTORY_SOURCE):
            services.delete_product_reference(instance)

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

_UNANNOTATED = object()


def endpoint_reference_id(reference: LocationFindingReference) -> int | None:
    """
    The id ``/api/v2/endpoints/`` shows for a status row's endpoint.

    That row is the finding's product's reference to the Location, so the legacy
    ``endpoint`` field joins straight back to the endpoints route.
    """
    annotated = getattr(reference, "endpoint_reference_id", _UNANNOTATED)
    if annotated is not _UNANNOTATED:
        return annotated
    return LocationProductReference.objects.filter(
        location_id=reference.location_id,
        product_id=reference.finding.test.engagement.product_id,
    ).values_list("id", flat=True).first()


class UserHasEndpointStatusCompatPermission(BasePermission):

    """
    The legacy Endpoint_Status permission, on LocationFindingReference rows.

    Linking a finding to an endpoint needs edit on both. Reading a row needs view on its
    finding, editing or deleting it edit, and pointing it at another endpoint or finding
    needs edit on that one too.
    """

    @staticmethod
    def _endpoint_editable(request, endpoint_id) -> bool:
        reference = get_object_or_404(LocationProductReference, pk=endpoint_id)
        return check_object_permission(request, reference.product, "view", "edit", "edit", "edit")

    def has_permission(self, request, view):
        if request.method != "POST":
            return True
        endpoint_id = request.data.get("endpoint")
        if endpoint_id is None:
            msg = "Unable to check for permissions: Attribute 'endpoint' is required"
            raise ParseError(msg)
        return self._endpoint_editable(request, endpoint_id) and check_post_permission(
            request, Finding, "finding", "edit",
        )

    def has_object_permission(self, request, view, obj):
        if not check_object_permission(request, obj.finding, "view", "edit", "edit"):
            return False
        if request.method in {"PUT", "PATCH"}:
            endpoint_id = request.data.get("endpoint")
            if endpoint_id is not None and str(endpoint_id) != str(endpoint_reference_id(obj)) and not self._endpoint_editable(request, endpoint_id):
                return False
        return check_update_permission(request, obj, "edit", "finding")


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
        # An endpoint is one product's reference to a Location, and the Location is shared, so
        # match its statuses through that product's findings only -- the rows a legacy
        # Endpoint_Status filter on that endpoint returned -- and only for a reference the
        # caller may see.
        reference = get_authorized_location_product_reference(
            "view", user=getattr(getattr(self, "request", None), "user", None),
        ).filter(id=value).first()
        if reference is None:
            return queryset.none()
        return queryset.filter(
            location_id=reference.location_id,
            finding__test__engagement__product_id=reference.product_id,
        )

    class Meta:
        model = LocationFindingReference
        fields = ["mitigated", "false_positive", "out_of_scope", "risk_accepted", "mitigated_by", "finding", "endpoint"]


class _StatusFlagField(BooleanField):

    """A legacy Endpoint_Status flag, read from and written to the reference's single status."""

    def __init__(self, flag_status, **kwargs):
        self.flag_status = flag_status
        super().__init__(required=False, **kwargs)

    def get_attribute(self, instance):
        return instance.status == self.flag_status


class _EndpointReferenceField(PrimaryKeyRelatedField):

    """The status row's endpoint, by the id ``/api/v2/endpoints/`` shows for it."""

    def use_pk_only_optimization(self):
        return False

    def get_attribute(self, instance):
        return instance

    def to_representation(self, value):
        return endpoint_reference_id(value)


class _MitigatedByField(PrimaryKeyRelatedField):

    """Who mitigated the row: the reference's auditor, while it is mitigated."""

    def get_attribute(self, instance):
        if instance.status != FindingLocationStatus.Mitigated or instance.auditor_id is None:
            return None
        return PKOnlyObject(pk=instance.auditor_id)


class _CreatedDateField(DateField):

    """The legacy ``date``: when the row was created. Accepted on writes and not stored."""

    def get_attribute(self, instance):
        return instance.created.date() if instance.created else None


class V3EndpointStatusCompatibleSerializer(ModelSerializer):

    """Serializes a LocationFindingReference model to something that looks like an Endpoint_Status."""

    date = _CreatedDateField(required=False)
    last_modified = DateTimeField(source="updated", read_only=True)

    mitigated = _StatusFlagField(FindingLocationStatus.Mitigated)
    mitigated_time = SerializerMethodField()
    mitigated_by = _MitigatedByField(queryset=Dojo_User.objects.all(), required=False, allow_null=True)
    false_positive = _StatusFlagField(FindingLocationStatus.FalsePositive)
    out_of_scope = _StatusFlagField(FindingLocationStatus.OutOfScope)
    risk_accepted = _StatusFlagField(FindingLocationStatus.RiskAccepted)

    endpoint = _EndpointReferenceField(
        queryset=LocationProductReference.objects.filter(location__location_type=URL.LOCATION_TYPE),
        required=False,
        allow_null=True,
    )
    location_id = IntegerField(source="location.id", read_only=True)

    def get_mitigated_time(self, obj) -> datetime.datetime | None:
        return obj.audit_time if obj.status == FindingLocationStatus.Mitigated else None

    class Meta:
        model = LocationFindingReference
        exclude = ("location",)
        read_only_fields = ("status", "auditor", "audit_time", "relationship", "relationship_data")

    def validate(self, attrs):
        endpoint = attrs.get("endpoint")
        finding = attrs.get("finding")
        if self.instance is None:
            if endpoint is None:
                raise drf_serializers.ValidationError({"endpoint": "This field is required."})
            if endpoint.product_id != finding.test.engagement.product_id:
                msg = "endpoint and finding must belong to the same product"
                raise drf_serializers.ValidationError(msg)
            if LocationFindingReference.objects.filter(location_id=endpoint.location_id, finding=finding).exists():
                msg = "This endpoint-finding relation already exists"
                raise drf_serializers.ValidationError(msg)
            return attrs

        # Mirrors the legacy order: a pair that names another existing row is reported as a
        # duplicate first, then any change to the pair is refused.
        location_id = endpoint.location_id if endpoint is not None else self.instance.location_id
        finding_id = finding.pk if finding is not None else self.instance.finding_id
        if (location_id, finding_id) != (self.instance.location_id, self.instance.finding_id) and (
            LocationFindingReference.objects.filter(location_id=location_id, finding_id=finding_id).exists()
        ):
            msg = "This endpoint-finding relation already exists"
            raise drf_serializers.ValidationError(msg)
        if endpoint is not None and endpoint.pk != endpoint_reference_id(self.instance):
            msg = "endpoint cannot be changed after creation"
            raise drf_serializers.ValidationError(msg)
        if finding is not None and finding.pk != self.instance.finding_id:
            msg = "finding cannot be changed after creation"
            raise drf_serializers.ValidationError(msg)
        return attrs

    @staticmethod
    def _flags(validated_data) -> dict[str, bool]:
        return {flag: validated_data[flag] for flag, _ in services.ENDPOINT_STATUS_FLAGS if flag in validated_data}

    def create(self, validated_data):
        return services.create_finding_reference(
            validated_data["endpoint"],
            validated_data["finding"],
            self._flags(validated_data),
            user=self.context["request"].user,
            mitigated_by=validated_data.get("mitigated_by"),
        )

    def update(self, instance, validated_data):
        return services.update_finding_reference(
            instance,
            self._flags(validated_data),
            user=self.context["request"].user,
            mitigated_by=validated_data.get("mitigated_by"),
        )


class V3EndpointStatusCompatibleViewSet(_ReloadAfterWriteMixin, PrefetchDojoModelViewSet):

    """ViewSet for LocationFindingReferences that behaves like EndpointStatusViewSet, reads and writes."""

    serializer_class = V3EndpointStatusCompatibleSerializer
    queryset = LocationFindingReference.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = V3EndpointStatusCompatibleFilterSet

    permission_classes = (
        IsAuthenticated,
        UserHasEndpointStatusCompatPermission,
    )

    def get_queryset(self):
        """Get authorized URLs using Endpoint authorization logic."""
        # The endpoint id per row, in the same query rather than one lookup per row.
        endpoint_reference = LocationProductReference.objects.filter(
            location=OuterRef("location"),
            product=OuterRef("finding__test__engagement__product"),
        ).values("id")[:1]
        return get_authorized_location_finding_reference("view").filter(
            location__location_type=URL.LOCATION_TYPE,
        ).annotate(
            endpoint_reference_id=Subquery(endpoint_reference),
        ).distinct()

    def perform_destroy(self, instance):
        with pghistory.context(source=PGHISTORY_SOURCE):
            services.delete_finding_reference(instance)
