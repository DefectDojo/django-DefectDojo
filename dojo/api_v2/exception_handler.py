import logging

from django.core.exceptions import ValidationError
from django.db.models.deletion import RestrictedError
from django.db.utils import IntegrityError
from django.utils.translation import gettext as _
from rest_framework.exceptions import ParseError
from rest_framework.response import Response
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


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if isinstance(exc, ParseError) and "JSON parse error" in str(exc):
        response = Response()
        response.status_code = HTTP_400_BAD_REQUEST
        response.data = {"message": _("JSON request content is malformed")}
    elif isinstance(exc, RestrictedError):
        # An object cannot be deleted because it has dependent objects.
        response = Response()
        response.status_code = HTTP_409_CONFLICT
        response.data = {}
        response.data["message"] = str(exc)
    elif isinstance(exc, ValidationError):
        response = Response()
        response.status_code = HTTP_400_BAD_REQUEST
        response.data = {}
        response.data["message"] = str(exc)
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
        logger.error(exc, exc_info=True)  # noqa: LOG014
        response = Response()
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        response.data = {}
        response.data[
            "message"
        ] = exception_message
        ErrorPageProductAnnouncement(response=response)
    elif response.status_code < 500:
        # HTTP status codes lower than 500 are no technical errors.
        # They need not to be logged and we provide the exception
        # message, if it is different from the detail that is already
        # in the response.
        if isinstance(response.data, dict) and str(
            exc,
        ) != response.data.get("detail", ""):
            response.data["message"] = str(exc)
            ErrorPageProductAnnouncement(response=response)
    else:
        # HTTP status code 500 or higher are technical errors.
        # They get logged and we don't change the response.
        logger.error(exc, exc_info=True)  # noqa: LOG014

    return response
