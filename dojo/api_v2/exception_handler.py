from django.db.models.deletion import RestrictedError
from rest_framework.response import Response
from rest_framework.status import HTTP_409_CONFLICT, HTTP_500_INTERNAL_SERVER_ERROR
from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if response is None:
        response = Response()
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        response.data = {}
        response.data['message'] = 'Internal server error, check logs for details'

    if isinstance(exc, RestrictedError):
        response.status_code = HTTP_409_CONFLICT
        response.data['message'] = str(exc)

    return response
