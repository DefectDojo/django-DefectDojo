from __future__ import annotations

from dojo.api_helpers.filters import StaticMethodFilters
from dojo.location.api.filters import AbstractedLocationFilter


class URLFilter(AbstractedLocationFilter):

    """Filter for the URL Model."""

    StaticMethodFilters.create_char_filters("protocol", "Protocol", locals())
    StaticMethodFilters.create_char_filters("host", "Host", locals())
    StaticMethodFilters.create_char_filters("path", "Path", locals())
    StaticMethodFilters.create_integer_filters("port", "Port", locals())
    StaticMethodFilters.create_char_filters("query", "Query Parameters", locals())
    StaticMethodFilters.create_char_filters("fragment", "Fragment", locals())
    StaticMethodFilters.create_ordering_filters(
        locals(),
        (
            "id",
            "protocol",
            "host",
            "path",
            "port",
            "query",
            "fragment",
            "created_at",
            "updated_at",
        ),
    )
