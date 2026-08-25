"""
The sunset contract for the deprecated Endpoint API surface.

Imports nothing on purpose: ``dojo.api_v2.exception_handler`` imports this at
request time and must not pull the model layer in behind it.
"""

SUNSET_CODE = "endpoint_api_sunset"

DOCS_URL = "https://docs.defectdojo.com/asset_modelling/locations/pro__migrating_from_endpoints/"

SUNSET_MESSAGE = (
    "The Endpoint API is not available on instances with Locations enabled. "
    "Reads are served from Locations; writes are not available."
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
