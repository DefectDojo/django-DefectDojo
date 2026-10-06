import json
from pathlib import Path

from django.core.serializers.json import DjangoJSONEncoder
from django.http import FileResponse, StreamingHttpResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response

from dojo.authorization.api_permissions import IsSuperUser
from dojo.export import services
from dojo.models import FileUpload, Product, Risk_Acceptance

EXPORT_VERSION_HEADER = "X-DefectDojo-Export-Version"

MAX_FILE_BYTES_PARAMETER = OpenApiParameter(
    "max_file_bytes",
    OpenApiTypes.INT,
    OpenApiParameter.QUERY,
    required=False,
    description="Files larger than this many bytes are listed but not included.",
)


class NDJSONRenderer(BaseRenderer):
    media_type = "application/x-ndjson"
    format = "ndjson"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        return (json.dumps(data, cls=DjangoJSONEncoder) + "\n").encode()


class FileDownloadRenderer(BaseRenderer):
    media_type = "application/octet-stream"
    format = "bin"
    charset = None
    render_style = "binary"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        return json.dumps(data, cls=DjangoJSONEncoder).encode()


def file_response(field_file):
    msg = "File not found."
    if not field_file:
        raise NotFound(msg)
    try:
        handle = field_file.open("rb")
    except FileNotFoundError as error:
        raise NotFound(msg) from error
    return FileResponse(
        handle, as_attachment=True, filename=Path(field_file.name).name, content_type="application/octet-stream",
    )


def int_param(request, name: str, default: int, minimum: int, maximum: int) -> int:
    raw = request.query_params.get(name)
    if raw in {None, ""}:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValidationError({name: "Must be an integer."}) from error
    if not minimum <= value <= maximum:
        raise ValidationError({name: f"Must be between {minimum} and {maximum}."})
    return value


class ExportViewSet(viewsets.ViewSet):
    permission_classes = (IsAuthenticated, IsSuperUser)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    @extend_schema(
        parameters=[MAX_FILE_BYTES_PARAMETER],
        responses={200: OpenApiTypes.OBJECT},
        summary="Export manifest",
        description="Counts, products, users and reference data that a product export includes. Superusers only.",
    )
    @action(detail=False, methods=["get"], url_path="manifest")
    def manifest(self, request):
        max_file_bytes = int_param(
            request, "max_file_bytes", services.DEFAULT_MAX_FILE_BYTES, 0, services.MAX_FILE_BYTES_LIMIT,
        )
        response = Response(services.build_manifest(max_file_bytes=max_file_bytes))
        response[EXPORT_VERSION_HEADER] = str(services.EXPORT_API_VERSION)
        return response

    @extend_schema(
        parameters=[
            OpenApiParameter("product_id", OpenApiTypes.INT, OpenApiParameter.PATH),
            OpenApiParameter("cursor", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                             description="The next value from the previous page. Empty for the first page."),
            OpenApiParameter("limit", OpenApiTypes.INT, OpenApiParameter.QUERY, required=False,
                             description="Most object lines on one page (1 to 5000)."),
            OpenApiParameter("include_duplicates", OpenApiTypes.BOOL, OpenApiParameter.QUERY, required=False),
            MAX_FILE_BYTES_PARAMETER,
            OpenApiParameter("max_pair_bytes", OpenApiTypes.INT, OpenApiParameter.QUERY, required=False,
                             description="Budget per finding for its request and response pairs, in bytes of "
                                         "base64 text: 0 to 67108864, default 16777216. The export keeps pairs in "
                                         "id order until one does not fit. It leaves out that pair and every later "
                                         "pair, and request_response_omitted counts them."),
        ],
        responses={(200, "application/x-ndjson"): OpenApiTypes.STR},
        summary="Export one product",
        description="One page of a product's engagements, tests, findings, finding groups and risk acceptances "
                    "as newline-delimited JSON. Superusers only.",
    )
    @action(detail=False, methods=["get"], url_path=r"products/(?P<product_id>\d+)")
    def products(self, request, product_id=None):
        product = Product.objects.filter(pk=product_id).select_related(
            "prod_type", "sla_configuration", "product_manager", "technical_contact", "team_manager",
        ).first()
        if product is None:
            msg = "Product not found."
            raise NotFound(msg)
        try:
            cursor = services.Cursor.decode(request.query_params.get("cursor") or "")
        except ValueError as error:
            raise ValidationError({"cursor": "Invalid cursor."}) from error
        options = services.ExportOptions(
            limit=int_param(request, "limit", services.DEFAULT_PAGE_LIMIT, 1, services.MAX_PAGE_LIMIT),
            max_file_bytes=int_param(
                request, "max_file_bytes", services.DEFAULT_MAX_FILE_BYTES, 0, services.MAX_FILE_BYTES_LIMIT,
            ),
            max_pair_bytes=int_param(
                request, "max_pair_bytes", services.DEFAULT_MAX_PAIR_BYTES, 0, services.MAX_PAIR_BYTES_LIMIT,
            ),
            include_duplicates=request.query_params.get("include_duplicates", "false").lower() == "true",
        )
        response = StreamingHttpResponse(
            services.product_page(product, cursor, options),
            content_type="application/x-ndjson",
        )
        response[EXPORT_VERSION_HEADER] = str(services.EXPORT_API_VERSION)
        return response

    @extend_schema(
        parameters=[OpenApiParameter("file_id", OpenApiTypes.INT, OpenApiParameter.PATH)],
        responses={(200, "application/octet-stream"): OpenApiTypes.BINARY},
        summary="Export one file",
        description="The bytes of one finding, test or engagement file. Superusers only.",
    )
    @action(detail=False, methods=["get"], url_path=r"files/(?P<file_id>\d+)", renderer_classes=[FileDownloadRenderer])
    def files(self, request, file_id=None):
        upload = FileUpload.objects.filter(pk=file_id).first()
        return file_response(upload.file if upload else None)

    @extend_schema(
        parameters=[OpenApiParameter("acceptance_id", OpenApiTypes.INT, OpenApiParameter.PATH)],
        responses={(200, "application/octet-stream"): OpenApiTypes.BINARY},
        summary="Export one risk acceptance proof",
        description="The proof file of one risk acceptance. Superusers only.",
    )
    @action(
        detail=False, methods=["get"], url_path=r"risk_acceptances/(?P<acceptance_id>\d+)/proof",
        renderer_classes=[FileDownloadRenderer],
    )
    def proof(self, request, acceptance_id=None):
        acceptance = Risk_Acceptance.objects.filter(pk=acceptance_id).first()
        return file_response(acceptance.path if acceptance else None)
