from dojo.models import System_Settings
from django.core.exceptions import ValidationError
from django.db.models.deletion import RestrictedError
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_409_CONFLICT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if isinstance(exc, RestrictedError):
        response = Response()
        response.status_code = HTTP_409_CONFLICT
        response.data = {"message": str(exc)}
    elif isinstance(exc, ValidationError):
        response = Response()
        response.status_code = HTTP_400_BAD_REQUEST
        response.data = {"message": str(exc)}
    else:
        if response is None:
            response = Response()
            response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
            response.data = {}
            if System_Settings.objects.get().api_expose_error_details:
                response.data["message"] = str(exc.args[0])
            else:
                response.data["message"] = "Internal server error, check logs for details"

    return response
