"""
Error contract for API v3 (D9 / §4.10) and the shared success renderer.

All error bodies are RFC 9457 ``application/problem+json`` with a ``fields`` extension for
validation errors. Routes never hand-build error bodies -- they raise ``ProblemDetail`` (or a
standard Django/ninja exception) and the registered handlers shape the response. Invariant I9:
the error contract is closed; new error kinds get new ``type`` URIs, not new shapes.

The shared success renderer (``json_response``) lives here too because it shares the JSON
encoder and the ``X-API-Status`` header logic with the problem renderer.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.serializers.json import DjangoJSONEncoder
from django.http import Http404, JsonResponse
from ninja.errors import AuthenticationError, ValidationError

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse
    from ninja import NinjaAPI

logger = logging.getLogger(__name__)

_ERROR_TYPE_BASE = "https://docs.defectdojo.com/api/v3/errors/"


class V3JSONEncoder(DjangoJSONEncoder):

    """
    DjangoJSONEncoder already renders aware datetimes as ISO-8601 with a ``Z`` suffix and dates
    as ``YYYY-MM-DD`` (§4.11). We normalise aware datetimes to UTC first so the ``Z`` conversion
    always applies regardless of the active timezone.
    """

    def default(self, o):
        import datetime  # noqa: PLC0415 -- localized to the encoder hot path

        if isinstance(o, datetime.datetime) and o.tzinfo is not None:
            o = o.astimezone(datetime.UTC)
        return super().default(o)


def _with_status_header(response: HttpResponse) -> HttpResponse:
    response["X-API-Status"] = settings.API_V3_STATUS
    return response


def json_response(data, *, status: int = 200) -> JsonResponse:
    """Shared success renderer: JSON body + ``X-API-Status`` header, v3 datetime conventions."""
    response = JsonResponse(data, status=status, encoder=V3JSONEncoder, safe=False)
    return _with_status_header(response)


def problem_response(
    request: HttpRequest,
    *,
    status: int,
    error_type: str,
    title: str,
    detail: str | None = None,
    fields: dict | None = None,
) -> JsonResponse:
    """Build an RFC 9457 ``application/problem+json`` response (§4.10)."""
    body: dict = {
        "type": _ERROR_TYPE_BASE + error_type,
        "title": title,
        "status": status,
    }
    if detail is not None:
        body["detail"] = detail
    if fields is not None:
        body["fields"] = fields
    response = JsonResponse(body, status=status, encoder=V3JSONEncoder)
    response["Content-Type"] = "application/problem+json"
    return _with_status_header(response)


class ProblemDetail(Exception):  # noqa: N818 -- RFC 9457 "problem detail"; not an "*Error" by name

    """
    Raise from routes/kernel to emit a problem+json response. The single registered handler
    shapes it, so callers never touch response objects (keeps I9 honest).
    """

    def __init__(
        self,
        *,
        status: int,
        error_type: str,
        title: str,
        detail: str | None = None,
        fields: dict | None = None,
    ) -> None:
        super().__init__(title)
        self.status = status
        self.error_type = error_type
        self.title = title
        self.detail = detail
        self.fields = fields


# --- Convenience constructors for the common problem kinds -------------------------------------

def validation_problem(fields: dict, *, detail: str | None = None) -> ProblemDetail:
    n = len(fields)
    return ProblemDetail(
        status=400,
        error_type="validation",
        title="Validation failed",
        detail=detail if detail is not None else f"{n} field{'s' if n != 1 else ''} failed validation",
        fields=fields,
    )


def expand_problem(detail: str) -> ProblemDetail:
    return ProblemDetail(status=400, error_type="expand", title="Invalid expand", detail=detail)


def fields_problem(detail: str) -> ProblemDetail:
    # `?fields=` (§4.7) is a distinct capability from `?expand=`; a distinct type URI keeps the
    # error contract closed (I9: new error kinds get new type URIs, not new shapes).
    return ProblemDetail(status=400, error_type="fields", title="Invalid fields", detail=detail)


def filter_problem(detail: str) -> ProblemDetail:
    return ProblemDetail(status=400, error_type="filter", title="Invalid filter", detail=detail)


def pagination_problem(detail: str) -> ProblemDetail:
    return ProblemDetail(status=400, error_type="pagination", title="Invalid pagination", detail=detail)


def not_found_problem(detail: str = "Not found") -> ProblemDetail:
    # 404 for unknown *or unauthorized* objects -- never leak existence (§4.10).
    return ProblemDetail(status=404, error_type="not-found", title="Not found", detail=detail)


# --- Handler registration ---------------------------------------------------------------------

def _handle_problem_detail(request: HttpRequest, exc: ProblemDetail) -> JsonResponse:
    return problem_response(
        request,
        status=exc.status,
        error_type=exc.error_type,
        title=exc.title,
        detail=exc.detail,
        fields=exc.fields,
    )


def _handle_ninja_validation(request: HttpRequest, exc: ValidationError) -> JsonResponse:
    # Reshape ninja/pydantic request-validation errors into the field-keyed contract (§4.10).
    fields: dict[str, list[str]] = {}
    for err in exc.errors:
        loc = err.get("loc", ())
        # Drop the leading source segment ("body"/"query"/"form"/"path") for a clean field name.
        parts = [str(p) for p in loc[1:]] if loc and loc[0] in {"body", "query", "form", "path"} else [str(p) for p in loc]
        key = ".".join(parts) if parts else "non_field_errors"
        fields.setdefault(key, []).append(err.get("msg", "Invalid value."))
    return _handle_problem_detail(request, validation_problem(fields))


def _handle_auth_error(request: HttpRequest, exc: AuthenticationError) -> JsonResponse:
    return problem_response(
        request,
        status=401,
        error_type="unauthorized",
        title="Authentication required",
        detail="Valid authentication credentials were not provided.",
    )


def _handle_permission_denied(request: HttpRequest, exc: PermissionDenied) -> JsonResponse:
    return problem_response(
        request,
        status=403,
        error_type="forbidden",
        title="Permission denied",
        detail="You do not have permission to perform this action.",
    )


def _handle_not_found(request: HttpRequest, exc: Http404) -> JsonResponse:
    return problem_response(
        request,
        status=404,
        error_type="not-found",
        title="Not found",
        detail="Not found",
    )


_DRF_ERROR_TYPES = {400: "validation", 401: "unauthorized", 403: "forbidden", 404: "not-found"}
_DRF_ERROR_TITLES = {
    400: "Validation failed",
    401: "Authentication required",
    403: "Permission denied",
    404: "Not found",
}


def _handle_drf_api_exception(request: HttpRequest, exc) -> JsonResponse:
    """
    Boundary adapter: v3 reuses v2 permission/import helpers that raise DRF ``APIException``
    subclasses (PermissionDenied/ValidationError/NotFound). Map them onto the closed problem+json
    contract so a reused helper never leaks a 500 (I9).
    """
    status = getattr(exc, "status_code", 400)
    detail = getattr(exc, "detail", str(exc))
    error_type = _DRF_ERROR_TYPES.get(status, "error")
    title = _DRF_ERROR_TITLES.get(status, "Error")
    if isinstance(detail, dict):
        fields = {k: (v if isinstance(v, list) else [str(v)]) for k, v in detail.items()}
        return problem_response(request, status=status, error_type=error_type, title=title, fields=fields)
    detail_str = "; ".join(str(d) for d in detail) if isinstance(detail, list) else str(detail)
    return problem_response(request, status=status, error_type=error_type, title=title, detail=detail_str)


def register_exception_handlers(api: NinjaAPI) -> None:
    """Register every v3 problem+json handler on the given NinjaAPI instance."""
    from rest_framework.exceptions import APIException  # noqa: PLC0415 -- boundary adapter only

    api.add_exception_handler(ProblemDetail, _handle_problem_detail)
    api.add_exception_handler(ValidationError, _handle_ninja_validation)
    api.add_exception_handler(AuthenticationError, _handle_auth_error)
    api.add_exception_handler(PermissionDenied, _handle_permission_denied)
    api.add_exception_handler(Http404, _handle_not_found)
    api.add_exception_handler(APIException, _handle_drf_api_exception)
