from rest_framework.exceptions import APIException
from rest_framework import status


class ApiError(APIException):

    def __init__(self, detail, code=None, message=""):
        self.detail = detail
        self.code = code
        self.message = message

    @classmethod
    def integrity_error(cls, contex):
        return cls(contex)
        
    @classmethod
    def bad_request(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_400_BAD_REQUEST,
            message="Bad Request"
        )

    @classmethod
    def unauthorized(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_401_UNAUTHORIZED,
            message="Unauthorized"
        )

    @classmethod
    def payment_required(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_402_PAYMENT_REQUIRED,
            message="Payment Required"
        )

    @classmethod
    def forbidden(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_403_FORBIDDEN,
            message="Forbidden"
        )

    @classmethod
    def not_found(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_404_NOT_FOUND,
            message="Not Found"
        )

    @classmethod
    def method_not_allowed(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_405_METHOD_NOT_ALLOWED,
            message="Method Not Allowed"
        )

    @classmethod
    def not_acceptable(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_406_NOT_ACCEPTABLE,
            message="Not Acceptable"
        )

    @classmethod
    def proxy_authentication_required(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_407_PROXY_AUTHENTICATION_REQUIRED,
            message="Proxy Authentication Required"
        )

    @classmethod
    def request_timeout(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_408_REQUEST_TIMEOUT,
            message="Request Timeout"
        )

    @classmethod
    def conflict(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_409_CONFLICT,
            message="Conflict"
        )

    @classmethod
    def gone(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_410_GONE,
            message="Gone"
        )

    @classmethod
    def length_required(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_411_LENGTH_REQUIRED,
            message="Length Required"
        )

    @classmethod
    def precondition_failed(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_412_PRECONDITION_FAILED,
            message="Precondition Failed"
        )

    @classmethod
    def request_entity_too_large(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            message="Request Entity Too Large"
        )

    @classmethod
    def request_uri_too_long(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_414_REQUEST_URI_TOO_LONG,
            message="Request URI Too Long"
        )

    @classmethod
    def unsupported_media_type(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            message="Unsupported Media Type"
        )

    @classmethod
    def requested_range_not_satisfiable(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE,
            message="Requested Range Not Satisfiable"
        )

    @classmethod
    def expectation_failed(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_417_EXPECTATION_FAILED,
            message="Expectation Failed"
        )

    @classmethod
    def misdirected_request(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_421_MISDIRECTED_REQUEST,
            message="Misdirected Request"
        )

    @classmethod
    def unprocessable_entity(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            message="Unprocessable Entity"
        )

    @classmethod
    def locked(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_423_LOCKED,
            message="Locked"
        )

    @classmethod
    def failed_dependency(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_424_FAILED_DEPENDENCY,
            message="Failed Dependency"
        )

    @classmethod
    def too_early(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_425_TOO_EARLY,
            message="Too Early"
        )

    @classmethod
    def upgrade_required(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_426_UPGRADE_REQUIRED,
            message="Upgrade Required"
        )

    @classmethod
    def precondition_required(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_428_PRECONDITION_REQUIRED,
            message="Precondition Required"
        )

    @classmethod
    def too_many_requests(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_429_TOO_MANY_REQUESTS,
            message="Too Many Requests"
        )

    @classmethod
    def request_header_fields_too_large(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
            message="Request Header Fields Too Large"
        )

    @classmethod
    def unavailable_for_legal_reasons(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_451_UNAVAILABLE_FOR_LEGAL_REASONS,
            message="Unavailable For Legal Reasons"
        )
    
    @classmethod
    def internal_server_error(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="Internal Server Error"
        )

    @classmethod
    def not_implemented(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_501_NOT_IMPLEMENTED,
            message="Not Implemented"
        )

    @classmethod
    def bad_gateway(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_502_BAD_GATEWAY,
            message="Bad Gateway"
        )

    @classmethod
    def service_unavailable(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_503_SERVICE_UNAVAILABLE,
            message="Service Unavailable"
        )

    @classmethod
    def gateway_timeout(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_504_GATEWAY_TIMEOUT,
            message="Gateway Timeout"
        )

    @classmethod
    def http_version_not_supported(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_505_HTTP_VERSION_NOT_SUPPORTED,
            message="HTTP Version Not Supported"
        )

    @classmethod
    def variant_also_negotiates(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_506_VARIANT_ALSO_NEGOTIATES,
            message="Variant Also Negotiates"
        )

    @classmethod
    def insufficient_storage(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_507_INSUFFICIENT_STORAGE,
            message="Insufficient Storage"
        )

    @classmethod
    def loop_detected(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_508_LOOP_DETECTED,
            message="Loop Detected"
        )

    @classmethod
    def bandwidth_limit_exceeded(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_509_BANDWIDTH_LIMIT_EXCEEDED,
            message="Bandwidth Limit Exceeded"
        )

    @classmethod
    def not_extended(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_510_NOT_EXTENDED,
            message="Not Extended"
        )

    @classmethod
    def network_authentication_required(cls, detail):
        return cls(
            detail=detail,
            code=status.HTTP_511_NETWORK_AUTHENTICATION_REQUIRED,
            message="Network Authentication Required"
        )

    @classmethod
    def unique_constraint_error(cls, detail="", field_name=""):
        return cls(
            detail=detail,
            code=status.HTTP_400_BAD_REQUEST,
            message="Unique constraint violation"
        )

