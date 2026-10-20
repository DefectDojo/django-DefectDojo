from collections import defaultdict
from collections.abc import Iterator

from django.conf import settings
from django.db.models import Count, Prefetch, QuerySet
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from dojo import __version__
from dojo.api_v2.serializers import SLAConfigurationSerializer
from dojo.authorization.api_permissions import IsSuperUser
from dojo.development_environment.api.serializer import DevelopmentEnvironmentSerializer
from dojo.endpoint.models import Endpoint_Status
from dojo.export.api.serializers import (
    MAX_FILE_BYTES_DEFAULT,
    ExportEngagementSerializer,
    ExportFindingSerializer,
    ExportProductSerializer,
    ExportRiskAcceptanceSerializer,
    ExportTestSerializer,
    ExportUserSerializer,
)
from dojo.location.feature import locations_enabled
from dojo.location.models import LocationProductReference
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Endpoint,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    Note_Type,
    Product,
    Product_Type,
    Regulation,
    Risk_Acceptance,
    SLA_Configuration,
    Test,
    Test_Type,
)
from dojo.note_type.api.serializer import NoteTypeSerializer
from dojo.notes.helper import notes_prefetch
from dojo.regulations.api.serializer import RegulationSerializer
from dojo.test.api.serializer import TestTypeSerializer
from dojo.user.authentication import token_expires_at
from dojo.utils import get_system_setting
from dojo.vulnerability.queries import vulnerability_id_prefetch

EXPORT_CHUNK_SIZE = 500
DOCS_URL = "https://docs.defectdojo.com/automation/api/product_export/"
MAX_FILE_BYTES_PARAMETER = OpenApiParameter(
    "max_file_bytes",
    OpenApiTypes.INT,
    OpenApiParameter.QUERY,
    description=(
        "File size cap in bytes. The product export carries a file of this size or less inline as base64, "
        "and a larger file keeps its size with no data. The manifest counts larger files in files_over_cap."
    ),
    default=MAX_FILE_BYTES_DEFAULT,
)
SCHEMA_VERSION = 1
COUNT_KEYS = (
    "engagements", "tests", "findings", "endpoints", "notes", "files", "files_over_cap", "risk_acceptances", "finding_groups",
)


class NDJSONRenderer(BaseRenderer):
    media_type = "application/x-ndjson"
    format = "ndjson"

    def render(self, data, accepted_media_type=None, renderer_context=None) -> bytes:
        return JSONRenderer().render(data) + b"\n"


def source_block() -> dict:
    return {
        "version": __version__,
        "install_id": str(get_system_setting("install_id")),
        "url": settings.SITE_URL,
        "locations_enabled": locations_enabled(),
    }


def max_file_bytes_from(request) -> int:
    raw = request.query_params.get("max_file_bytes")
    if raw is None:
        return MAX_FILE_BYTES_DEFAULT
    message = {"max_file_bytes": "Must be an integer of 0 or more."}
    try:
        value = int(raw)
    except ValueError:
        raise ValidationError(message) from None
    if value < 0:
        raise ValidationError(message)
    return value


def finding_prefetch() -> tuple:
    return (
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
        "burprawrequestresponse_set",
        "finding_meta",
    )


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
        .order_by("id")
        .select_related(
            "test",
            "test__test_type",
            "test__engagement",
            "test__environment",
            "test__engagement__product",
            "test__engagement__product__prod_type",
        )
        .prefetch_related(*finding_prefetch(), endpoints)
    )


def engagement_queryset(product: Product) -> QuerySet:
    return (
        Engagement.objects.filter(product=product)
        .order_by("id")
        .prefetch_related(notes_prefetch(), "risk_acceptance", "files", "tags")
    )


def test_queryset(product: Product) -> QuerySet:
    return (
        Test.objects.filter(engagement__product=product)
        .order_by("id")
        .select_related("test_type")
        .prefetch_related(notes_prefetch(), "files", "tags", "finding_group_set__jira_issue")
    )


def risk_acceptance_queryset(product: Product) -> QuerySet:
    return (
        Risk_Acceptance.objects.filter(engagement__product=product)
        .distinct()
        .order_by("id")
        .prefetch_related(
            notes_prefetch(), "engagement_set", Prefetch("accepted_findings", queryset=Finding.objects.only("id")),
        )
    )


def _tally(counts: dict, finding_groups: set, line_type: str, data: dict) -> None:
    counts["notes"] += len(data["notes"])
    files = data.get("files", [])
    counts["files"] += len(files)
    counts["files_over_cap"] += sum(1 for entry in files if entry["data_base64"] is None and "error" not in entry)
    if line_type == "finding":
        counts["endpoints"] += len(data["endpoints"])
        finding_groups.update(group["id"] for group in data["finding_groups"])


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
        ("engagement", "engagements", ExportEngagementSerializer, engagement_queryset),
        ("test", "tests", ExportTestSerializer, test_queryset),
        ("finding", "findings", ExportFindingSerializer, finding_queryset),
        ("risk_acceptance", "risk_acceptances", ExportRiskAcceptanceSerializer, risk_acceptance_queryset),
    )
    for line_type, count_key, serializer_class, queryset in sections:
        serializer = serializer_class(context=context)
        for obj in queryset(product).iterator(chunk_size=EXPORT_CHUNK_SIZE):
            data = serializer.to_representation(obj)
            counts[count_key] += 1
            _tally(counts, finding_groups, line_type, data)
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
        ("notes", Risk_Acceptance.notes.through, "risk_acceptance__engagement__product_id"),
        ("risk_acceptances", Risk_Acceptance, "engagement__product_id"),
        ("finding_groups", Finding_Group, "test__engagement__product_id"),
    )
    for key, model, product_path in sources:
        # order_by() drops default orderings, which would otherwise split the GROUP BY per row.
        rows = model.objects.order_by().values_list(product_path).annotate(n=Count("id", distinct=True))
        for product_id, n in rows:
            if product_id is not None:
                counts[product_id][key] += n
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
                over_cap[file_id] = name and storage.exists(name) and storage.size(name) > max_file_bytes
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
    token = request.auth if isinstance(request.auth, Token) else None
    users = Dojo_User.objects.select_related("usercontactinfo", "auth_token").order_by("id")
    return {
        "schema": SCHEMA_VERSION,
        "generated_at": timezone.now().isoformat(),
        "source": source_block(),
        "max_file_bytes": max_file_bytes,
        "token": {
            "username": request.user.username,
            "is_superuser": request.user.is_superuser,
            "expires_at": token_expires_at(token) if token else None,
        },
        "scan_types": sorted(
            Test.objects.exclude(scan_type=None).order_by().values_list("scan_type", flat=True).distinct(),
        ),
        "reference": {
            "sla_configurations": SLAConfigurationSerializer(SLA_Configuration.objects.order_by("id"), many=True).data,
            "development_environments": DevelopmentEnvironmentSerializer(
                Development_Environment.objects.order_by("id"), many=True,
            ).data,
            "regulations": RegulationSerializer(Regulation.objects.order_by("id"), many=True).data,
            "test_types": TestTypeSerializer(Test_Type.objects.order_by("id"), many=True).data,
            "note_types": NoteTypeSerializer(Note_Type.objects.order_by("id"), many=True).data,
            "users": ExportUserSerializer(users, many=True).data,
        },
        "product_types": product_types,
        "products": products,
        "totals": {"product_types": len(product_types), "products": len(products), **_summed(products)},
    }


class ProductExportView(APIView):
    permission_classes = (IsAuthenticated, IsSuperUser)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    @extend_schema(
        parameters=[MAX_FILE_BYTES_PARAMETER],
        responses={(200, "application/x-ndjson"): OpenApiTypes.STR},
        description=(
            "Superuser only. Streams one product with its engagements, tests, findings and risk acceptances "
            f"as NDJSON, one JSON object per line. The line shapes are documented at {DOCS_URL}"
        ),
    )
    def get(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        max_file_bytes = max_file_bytes_from(request)
        response = StreamingHttpResponse(
            product_lines(product, request, max_file_bytes), content_type="application/x-ndjson",
        )
        response["Content-Disposition"] = f'attachment; filename="defectdojo-product-{product.pk}-export.ndjson"'
        return response


class ExportManifestView(APIView):
    permission_classes = (IsAuthenticated, IsSuperUser)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    @extend_schema(
        parameters=[MAX_FILE_BYTES_PARAMETER],
        responses={200: OpenApiTypes.OBJECT},
        description=(
            "Superuser only. Lists the product types and products with their counts, the reference data "
            f"and the users that a product export refers to. The keys are documented at {DOCS_URL}"
        ),
    )
    def get(self, request):
        return Response(build_manifest(request, max_file_bytes_from(request)))
