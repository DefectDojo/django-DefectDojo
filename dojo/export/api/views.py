from collections.abc import Iterator

from django.conf import settings
from django.db.models import Prefetch, QuerySet
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from dojo import __version__
from dojo.authorization.api_permissions import IsSuperUser
from dojo.endpoint.models import Endpoint_Status
from dojo.export.api.serializers import (
    MAX_FILE_BYTES_DEFAULT,
    ExportEngagementSerializer,
    ExportFindingSerializer,
    ExportProductSerializer,
    ExportRiskAcceptanceSerializer,
    ExportTestSerializer,
)
from dojo.location.feature import locations_enabled
from dojo.models import Engagement, Finding, Product, Risk_Acceptance, Test
from dojo.notes.helper import notes_prefetch
from dojo.utils import get_system_setting
from dojo.vulnerability.queries import vulnerability_id_prefetch

EXPORT_CHUNK_SIZE = 500
SCHEMA_VERSION = 1
FINDING_PREFETCH = (
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
    value = request.query_params.get("max_file_bytes")
    if value is None:
        return MAX_FILE_BYTES_DEFAULT
    if not value.isdecimal():
        raise ValidationError({"max_file_bytes": "Must be an integer of 0 or more."})
    return int(value)


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
        .prefetch_related(*FINDING_PREFETCH, endpoints)
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
        .prefetch_related(notes_prefetch(), "engagement_set", "accepted_findings")
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
    counts = dict.fromkeys(
        ("engagements", "tests", "findings", "endpoints", "notes", "files", "files_over_cap", "risk_acceptances"), 0,
    )
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


class ProductExportView(APIView):
    permission_classes = (IsAuthenticated, IsSuperUser)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    def get(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        max_file_bytes = max_file_bytes_from(request)
        response = StreamingHttpResponse(
            product_lines(product, request, max_file_bytes), content_type="application/x-ndjson",
        )
        response["Content-Disposition"] = f'attachment; filename="defectdojo-product-{pk}-export.ndjson"'
        return response


class ExportManifestView(APIView):
    permission_classes = (IsAuthenticated, IsSuperUser)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    def get(self, request):
        return Response({})
