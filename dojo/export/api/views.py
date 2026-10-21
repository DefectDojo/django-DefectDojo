import math
from collections import defaultdict
from collections.abc import Iterator

from django.conf import settings
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import Count, Prefetch, Q, QuerySet
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.authtoken.models import Token
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from dojo import __version__
from dojo.api_v2.serializers import SLAConfigurationSerializer
from dojo.authorization.api_permissions import IsSuperUser
from dojo.development_environment.api.serializer import DevelopmentEnvironmentSerializer
from dojo.endpoint.models import Endpoint_Status
from dojo.export.api.serializers import (
    ExportEngagementSerializer,
    ExportFindingSerializer,
    ExportParamsSerializer,
    ExportProductSerializer,
    ExportRiskAcceptanceSerializer,
    ExportTestSerializer,
    ExportUserSerializer,
    file_size,
)
from dojo.location.feature import locations_enabled
from dojo.location.models import LocationProductReference
from dojo.models import (
    BurpRawRequestResponse,
    Dojo_User,
    Endpoint,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Risk_Acceptance,
    Test,
)
from dojo.note_type.api.serializer import NoteTypeSerializer
from dojo.notes.helper import notes_prefetch
from dojo.product_attributes.api.serializer import (
    ProductLifecycleSerializer,
    ProductOriginSerializer,
    ProductPlatformSerializer,
)
from dojo.regulations.api.serializer import RegulationSerializer
from dojo.test.api.serializer import TestTypeSerializer
from dojo.user.authentication import token_expires_at
from dojo.utils import get_system_setting
from dojo.vulnerability.queries import vulnerability_id_prefetch

EXPORT_CHUNK_SIZE = 500
DOCS_URL = "https://docs.defectdojo.com/automation/api/product_export/"
SCHEMA_VERSION = 1
COUNT_KEYS = (
    "engagements", "tests", "findings", "endpoints", "notes", "files", "files_over_cap", "risk_acceptances", "finding_groups",
)
REFERENCE_SERIALIZERS = {
    "sla_configurations": SLAConfigurationSerializer,
    "development_environments": DevelopmentEnvironmentSerializer,
    "regulations": RegulationSerializer,
    "test_types": TestTypeSerializer,
    "note_types": NoteTypeSerializer,
    "product_platforms": ProductPlatformSerializer,
    "product_lifecycles": ProductLifecycleSerializer,
    "product_origins": ProductOriginSerializer,
}


class NDJSONRenderer(BaseRenderer):
    media_type = "application/x-ndjson"
    format = "ndjson"

    def render(self, data, accepted_media_type=None, renderer_context=None) -> bytes:
        try:
            line = JSONRenderer().render(data)
        except ValueError:
            line = JSONRenderer().render(finite(data))
        # DRF escapes U+2028 and U+2029 but not U+0085, and str.splitlines() splits on all three.
        return line.replace(b"\xc2\x85", b"\\u0085") + b"\n"


def finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: finite(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [finite(item) for item in value]
    return value


def source_block() -> dict:
    return {
        "version": __version__,
        "install_id": str(get_system_setting("install_id")),
        "url": settings.SITE_URL,
        "locations_enabled": locations_enabled(),
    }


def max_file_bytes_from(request) -> int:
    params = ExportParamsSerializer(data=request.query_params)
    params.is_valid(raise_exception=True)
    return params.validated_data["max_file_bytes"]


def finding_queryset(product: Product) -> QuerySet:
    if locations_enabled():
        endpoints = "locations__location__tags"
    else:
        endpoints = Prefetch(
            "status_finding",
            queryset=Endpoint_Status.objects.select_related("endpoint").prefetch_related("endpoint__tags"),
        )
    return (
        Finding.objects.filter(test__engagement__product=product)
        .select_related("test", "test__test_type")
        .prefetch_related(
            notes_prefetch(),
            vulnerability_id_prefetch(),
            "finding_cwe_set",
            "reviewers",
            "found_by",
            "risk_acceptance_set",
            "tags",
            "jira_issue",
            "finding_group_set__jira_issue",
            "files",
            Prefetch("burprawrequestresponse_set", queryset=BurpRawRequestResponse.objects.order_by("id")),
            "finding_meta",
            endpoints,
        )
    )


def risk_acceptance_in(product: Product, prefix: str = "") -> Q:
    # An acceptance belongs to a product through an engagement link or through a finding it accepts.
    return Q(**{f"{prefix}engagement__product": product}) | Q(**{f"{prefix}accepted_findings__test__engagement__product": product})


def product_lines(product: Product, request, max_file_bytes: int) -> Iterator[bytes]:
    context = {"request": request, "max_file_bytes": max_file_bytes}
    render = NDJSONRenderer().render
    yield render({
        "type": "header",
        "schema": SCHEMA_VERSION,
        "generated_at": timezone.now().isoformat(),
        "max_file_bytes": max_file_bytes,
        "source": source_block(),
        "product": ExportProductSerializer(product, context=context).data,
    })
    counts = dict.fromkeys(COUNT_KEYS, 0)
    finding_groups = set()
    sections = (
        (
            "engagement",
            ExportEngagementSerializer,
            Engagement.objects.filter(product=product).prefetch_related(notes_prefetch(), "risk_acceptance", "files", "tags"),
        ),
        (
            "test",
            ExportTestSerializer,
            Test.objects.filter(engagement__product=product)
            .select_related("test_type")
            .prefetch_related(notes_prefetch(), "files", "tags", "finding_group_set__jira_issue"),
        ),
        ("finding", ExportFindingSerializer, finding_queryset(product)),
        (
            "risk_acceptance",
            ExportRiskAcceptanceSerializer,
            Risk_Acceptance.objects.filter(risk_acceptance_in(product))
            .distinct()
            .prefetch_related(
                notes_prefetch(), "engagement_set", Prefetch("accepted_findings", queryset=Finding.objects.only("id")),
            ),
        ),
    )
    for line_type, serializer_class, queryset in sections:
        serializer = serializer_class(context=context)
        for obj in queryset.order_by("id").iterator(chunk_size=EXPORT_CHUNK_SIZE):
            data = serializer.to_representation(obj)
            files = data.get("files", [])
            counts[f"{line_type}s"] += 1
            counts["notes"] += len(data["notes"])
            counts["files"] += len(files)
            counts["files_over_cap"] += sum(1 for entry in files if entry["data_base64"] is None and "error" not in entry)
            if line_type == "finding":
                counts["endpoints"] += len(data["endpoints"])
                finding_groups.update(group["id"] for group in data["finding_groups"])
            yield render({"type": line_type, "data": data})
    counts["finding_groups"] = len(finding_groups)
    yield render({"type": "end", "counts": counts})


def product_counts(max_file_bytes: int) -> dict[int, dict[str, int]]:
    counts = defaultdict(lambda: dict.fromkeys(COUNT_KEYS, 0))
    sources = (
        ("engagements", Engagement, "product_id"),
        ("tests", Test, "engagement__product_id"),
        ("findings", Finding, "test__engagement__product_id"),
        ("endpoints", LocationProductReference if locations_enabled() else Endpoint, "product_id"),
        # Count M2M through rows: the stream counts a shared note once per owner, not once.
        ("notes", Engagement.notes.through, "engagement__product_id"),
        ("notes", Test.notes.through, "test__engagement__product_id"),
        ("notes", Finding.notes.through, "finding__test__engagement__product_id"),
        ("finding_groups", Finding_Group, "test__engagement__product_id"),
    )
    for key, model, product_path in sources:
        # order_by() drops default orderings, which would otherwise split the GROUP BY per row.
        rows = model.objects.order_by().values_list(product_path).annotate(n=Count("id", distinct=True))
        for product_id, n in rows:
            if product_id is not None:
                counts[product_id][key] += n
    # A risk acceptance reaches a product through two paths, so collect ids per product and count the union.
    for key, model, prefix in (("risk_acceptances", Risk_Acceptance, ""), ("notes", Risk_Acceptance.notes.through, "risk_acceptance__")):
        ids = defaultdict(set)
        for path in (f"{prefix}engagement__product_id", f"{prefix}accepted_findings__test__engagement__product_id"):
            for product_id, found in model.objects.order_by().values_list(path).annotate(ids=ArrayAgg("id", distinct=True)):
                if product_id is not None:
                    ids[product_id].update(found)
        for product_id, found in ids.items():
            counts[product_id][key] += len(found)
    storage = FileUpload._meta.get_field("file").storage
    over_cap = {}
    file_sources = (
        (Engagement.files.through, "engagement__product_id"),
        (Test.files.through, "test__engagement__product_id"),
        (Finding.files.through, "finding__test__engagement__product_id"),
    )
    for through, product_path in file_sources:
        for product_id, file_id, name in through.objects.values_list(product_path, "fileupload_id", "fileupload__file"):
            if file_id not in over_cap:
                size = file_size(storage, name)
                over_cap[file_id] = size is not None and size > max_file_bytes
            counts[product_id]["files"] += 1
            if over_cap[file_id]:
                counts[product_id]["files_over_cap"] += 1
    return counts


def _summed(products: list[dict]) -> dict[str, int]:
    return {key: sum(product["counts"][key] for product in products) for key in COUNT_KEYS}


def build_manifest(request, max_file_bytes: int) -> dict:
    counts = product_counts(max_file_bytes)
    products = [
        {"id": pk, "name": name, "prod_type": prod_type_id, "counts": counts[pk]}
        for pk, name, prod_type_id in Product.objects.order_by("id").values_list("id", "name", "prod_type_id")
    ]
    members = defaultdict(list)
    for product in products:
        members[product["prod_type"]].append(product)
    product_types = [
        {"id": pk, "name": name, "counts": {"products": len(members[pk]), **_summed(members[pk])}}
        for pk, name in Product_Type.objects.order_by("id").values_list("id", "name")
    ]
    users = Dojo_User.objects.select_related("usercontactinfo", "auth_token").order_by("id")
    return {
        "schema": SCHEMA_VERSION,
        "generated_at": timezone.now().isoformat(),
        "source": source_block(),
        "max_file_bytes": max_file_bytes,
        "token": {
            "username": request.user.username,
            "is_superuser": request.user.is_superuser,
            "expires_at": token_expires_at(request.auth) if isinstance(request.auth, Token) else None,
        },
        "scan_types": sorted(
            Test.objects.exclude(scan_type=None).order_by().values_list("scan_type", flat=True).distinct(),
        ),
        "reference": {
            **{
                key: serializer(serializer.Meta.model.objects.order_by("id"), many=True).data
                for key, serializer in REFERENCE_SERIALIZERS.items()
            },
            "users": ExportUserSerializer(users, many=True).data,
        },
        "product_types": product_types,
        "products": products,
        "totals": {"product_types": len(product_types), "products": len(products), **_summed(products)},
    }


class ProductExportView(APIView):
    permission_classes = (IsSuperUser,)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    @extend_schema(
        parameters=[ExportParamsSerializer, OpenApiParameter("id", OpenApiTypes.INT, OpenApiParameter.PATH)],
        responses={(200, "application/x-ndjson"): OpenApiTypes.STR},
        description=(
            "Superuser only. Streams one product with its engagements, tests, findings and risk acceptances "
            f"as NDJSON, one JSON object per line. The line shapes are documented at {DOCS_URL}"
        ),
    )
    def get(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        return StreamingHttpResponse(
            product_lines(product, request, max_file_bytes_from(request)),
            content_type="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="defectdojo-product-{product.pk}-export.ndjson"',
                "X-Accel-Buffering": "no",
            },
        )


class ExportManifestView(APIView):
    permission_classes = (IsSuperUser,)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    @extend_schema(
        parameters=[ExportParamsSerializer],
        responses={200: OpenApiTypes.OBJECT},
        description=(
            "Superuser only. Lists the product types and products with their counts, the reference data "
            f"and the users that a product export refers to. The keys are documented at {DOCS_URL}"
        ),
    )
    def get(self, request):
        return Response(build_manifest(request, max_file_bytes_from(request)))
