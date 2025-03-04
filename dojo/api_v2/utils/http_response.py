from rest_framework.response import Response
from rest_framework import status

def custom_response(code, status, message="", data={}):
    return Response(
        status=code,
        data={
            "status": status,
            "code": code,
            "message": message,
            "data": data
        }
    )

def error(message="", data={}):
    return custom_response(code=status.HTTP_500_INTERNAL_SERVER_ERROR, status="error", message=message, data=data)

def bad_request(message="", data={}):
    return custom_response(code=status.HTTP_400_BAD_REQUEST, status="bad_request", message=message, data=data)

def ok(message="", data={}):
    return custom_response(code=status.HTTP_200_OK, status="success", message=message, data=data)


def created(message="", data={}):
    return custom_response(code=status.HTTP_201_CREATED, status="created", message=message, data=data)


def accepted(message="", data={}):
    return custom_response(code=status.HTTP_202_ACCEPTED, status="accepted", message=message, data=data)


def non_authoritative_information(message="", data={}):
    return custom_response(code=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION, status="non_authoritative_information", message=message, data=data)


def no_content(message="", data={}):
    return custom_response(code=status.HTTP_204_NO_CONTENT, status="no_content", message=message, data=data)


def reset_content(message="", data={}):
    return custom_response(code=status.HTTP_205_RESET_CONTENT, status="reset_content", message=message, data=data)


def partial_content(message="", data={}):
    return custom_response(code=status.HTTP_206_PARTIAL_CONTENT, status="partial_content", message=message, data=data)


def multi_status(message="", data={}):
    return custom_response(code=status.HTTP_207_MULTI_STATUS, status="multi_status", message=message, data=data)


def already_reported(message="", data={}):
    return custom_response(code=status.HTTP_208_ALREADY_REPORTED, status="already_reported", message=message, data=data)


def im_used(message="", data={}):
    return custom_response(code=status.HTTP_226_IM_USED, status="im_used", message=message, data=data)