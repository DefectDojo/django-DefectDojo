"""The sunset contract for the deprecated Endpoint API surface."""

SUNSET_CODE = "endpoint_api_sunset"

DOCS_URL = "https://docs.defectdojo.com/asset_modelling/locations/pro__migrating_from_endpoints/"

SUNSET_MESSAGE = (
    "This route still reads the deprecated Endpoint model, which is not available on "
    "instances with Locations enabled. /api/v2/endpoints/ and /api/v2/endpoint_status/ "
    "are served from Locations, for reads and writes."
)

DEFAULT_REPLACEMENT = "/api/v2/location/"


def sunset_body():
    """The response body a client branches on: a stable code, then where to go."""
    return {
        "code": SUNSET_CODE,
        "message": SUNSET_MESSAGE,
        "replacement": DEFAULT_REPLACEMENT,
        "docs": DOCS_URL,
    }
