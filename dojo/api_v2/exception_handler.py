import logging

from django.core.exceptions import NON_FIELD_ERRORS, ValidationError
from django.db.models.deletion import RestrictedError
from django.db.utils import IntegrityError
from django.utils.log import log_response
from django.utils.translation import gettext as _
from rest_framework.exceptions import ParseError
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_409_CONFLICT,
    HTTP_410_GONE,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from rest_framework.views import exception_handler

from dojo.endpoint.models import EndpointDeprecatedError
from dojo.location.api.deprecation import sunset_body
from dojo.models import System_Settings
from dojo.product_announcements import ErrorPageProductAnnouncement
from dojo.utils import restricted_delete_message

logger = logging.getLogger(__name__)

# SQLSTATE class 23505 = unique_violation. Checked on the driver exception Django
# wraps, so detection does not depend on the wording of the message.
UNIQUE_VIOLATION_SQLSTATE = "23505"

# Fallback for drivers that expose no SQLSTATE, and for IntegrityErrors raised
# without a wrapped cause.
UNIQUE_VIOLATION_MESSAGE_MARKERS = (
    "unique constraint",  # PostgreSQL
    "duplicate entry",  # MySQL / MariaDB
    "unique_violation",
)

# Deliberately generic: the driver message carries the constraint name, the table
# name and the offending value, none of which belong in an API response body.
UNIQUE_VIOLATION_RESPONSE_MESSAGE = (
    "The request conflicts with an existing record because a unique field value "
    "already exists. Retrieve or update the existing record instead of creating "
    "a new one."
)


def _is_unique_violation(exc) -> bool:
    """
    Return True when ``exc`` is a database unique-constraint violation.

    A unique violation means the caller asked for a record that is already
    there — a conflict it can resolve — whereas every other IntegrityError
    (foreign key, not-null, check constraint) points at a defect on our side
    and must keep surfacing as a 500.
    """
    # Django wraps the driver exception; psycopg exposes SQLSTATE as `sqlstate`
    # and psycopg2 as `pgcode`.
    cause = exc.__cause__
    for attribute in ("sqlstate", "pgcode"):
        if getattr(cause, attribute, None) == UNIQUE_VIOLATION_SQLSTATE:
            return True

    text = str(exc).lower()
    return any(marker in text for marker in UNIQUE_VIOLATION_MESSAGE_MARKERS)


def _log_server_error(exc, context, response):
    request = (context or {}).get("request")
    if request is None:
        logger.error(exc, exc_info=True)  # noqa: LOG014
        return
    # Django only attaches the traceback to its django.request record (and so to
    # the admin error email) for exceptions it catches itself. Log it here with the
    # exception, which also marks the response so Django does not log it again.
    log_response(
        "%s: %s",
        response.reason_phrase,
        request.path,
        response=response,
        request=getattr(request, "_request", request),
        exception=exc,
    )


# A message that does not end a sentence gets a period, so the next field's message does not run on from it.
SENTENCE_ENDS = (".", "!", "?", "\u3002", "\uff01", "\uff1f")
# Keys of an error map that hold messages rather than name a field: DRF's non-field key, Django's ("__all__"),
# and a "detail" a view raised itself.
UNNAMED_ERROR_KEYS = frozenset({"detail", NON_FIELD_ERRORS})


def _readable_validation_message(detail, path=()):
    """
    The messages of a serializer or Django ``ValidationError`` as plain sentences.

    Each field's messages follow its name (a nested field's dotted path); messages that name no field
    (``non_field_errors``, Django's ``__all__``, ``detail``) read without one. ``str()`` of the error would be a
    Python repr instead.
    """
    if isinstance(detail, dict):
        unnamed = UNNAMED_ERROR_KEYS | {api_settings.NON_FIELD_ERRORS_KEY}
        parts = (_readable_validation_message(value, path if key in unnamed else (*path, str(key))) for key, value in detail.items())
        return " ".join(part for part in parts if part)
    if isinstance(detail, (list, tuple)):
        return " ".join(part for part in (_readable_validation_message(value, path) for value in detail) if part)
    message = str(detail).strip()
    if not message:
        return ""
    if not message.endswith(SENTENCE_ENDS):
        message += "."
    return f"{'.'.join(path)}: {message}" if path else message


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if isinstance(exc, ParseError) and "JSON parse error" in str(exc):
        response = Response()
        response.status_code = HTTP_400_BAD_REQUEST
        response.data = {"message": _("JSON request content is malformed")}
    elif isinstance(exc, RestrictedError):
        # An object cannot be deleted because it has dependent objects; say how many and of which kinds.
        response = Response()
        response.status_code = HTTP_409_CONFLICT
        response.data = {"message": restricted_delete_message(exc)}
    elif isinstance(exc, ValidationError):
        response = Response()
        response.status_code = HTTP_400_BAD_REQUEST
        response.data = {}
        # Its messages as sentences, each field's after its name; str() of the error is a list or dict repr.
        # An error with no message text gets no "message", as an empty serializer error map does.
        messages = exc.message_dict if hasattr(exc, "error_dict") else exc.messages
        if message := _readable_validation_message(messages):
            response.data["message"] = message
        ErrorPageProductAnnouncement(response=response)
    elif isinstance(exc, IntegrityError) and _is_unique_violation(exc):
        # The row the caller wanted to create already exists. Serializers built
        # from a unique model field do check first, but that SELECT and the
        # INSERT are not atomic, so concurrent writers both pass validation and
        # the loser lands here. That is a conflict the caller can act on, not a
        # server fault, so answer 409 rather than letting it fall through to the
        # generic 500 branch below.
        # Logged at info, not error: this is an expected outcome of concurrent
        # writers, and logging it as an error keeps it in error reporting where
        # it reads as an outage.
        logger.info(
            "unique constraint violation on %s: %s",
            (context or {}).get("request", "unknown request"),
            exc,
        )
        response = Response()
        response.status_code = HTTP_409_CONFLICT
        # Matching the RestrictedError 409 above, no product announcement is
        # attached to a conflict response.
        response.data = {"message": UNIQUE_VIOLATION_RESPONSE_MESSAGE}
    elif isinstance(exc, EndpointDeprecatedError):
        # A v2 route reached the deprecated Endpoint model. Answer the documented
        # sunset contract rather than the generic 500 below, and log at info: an
        # expected, documented answer reads as an outage in error reporting.
        # This branch only catches exceptions raised during DRF's dispatch.
        logger.info(
            "endpoint api sunset on %s",
            (context or {}).get("request", "unknown request"),
        )
        response = Response(sunset_body())
        response.status_code = HTTP_410_GONE
    elif response is None:
        if System_Settings.objects.get().api_expose_error_details:
            exception_message = str(exc.args[0])
        else:
            exception_message = _("Internal server error, check logs for details")
        # There is no standard error response, so we assume an unexpected
        # exception. It is logged but no details are given to the user,
        # to avoid leaking internal technical information.
        response = Response()
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        response.data = {}
        response.data[
            "message"
        ] = exception_message
        _log_server_error(exc, context, response)
        ErrorPageProductAnnouncement(response=response)
    elif response.status_code < 500:
        # HTTP status codes lower than 500 are no technical errors.
        # They need not to be logged and we provide the exception
        # message, if it is different from the detail that is already
        # in the response.
        if isinstance(exc, DRFValidationError) and isinstance(response.data, dict):
            # The field map says it already; the message repeats it as sentences callers can show. An error map
            # that has its own "message" key keeps it, and an empty one gets no message.
            if "message" not in response.data and (message := _readable_validation_message(exc.detail)):
                response.data["message"] = message
            ErrorPageProductAnnouncement(response=response)
        elif isinstance(response.data, dict) and str(
            exc,
        ) != response.data.get("detail", ""):
            response.data["message"] = str(exc)
            ErrorPageProductAnnouncement(response=response)
    else:
        # HTTP status code 500 or higher are technical errors.
        # They get logged and we don't change the response.
        _log_server_error(exc, context, response)

    return response
