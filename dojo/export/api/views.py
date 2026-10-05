import json

from django.core.serializers.json import DjangoJSONEncoder
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response

from dojo.authorization.api_permissions import IsSuperUser
from dojo.export import services

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
