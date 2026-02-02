from __future__ import annotations

from django_filters import CharFilter

from dojo.api_helpers.filters import StaticMethodFilters
from dojo.location.api.filters import AbstractedLocationFilter


class URLFilter(AbstractedLocationFilter):

    """Filter for the URL Model."""

    StaticMethodFilters.create_char_filters("protocol", "Protocol", locals())
    StaticMethodFilters.create_char_filters("user_info", "User Info", locals())
    StaticMethodFilters.create_char_filters("host", "Host", locals())
    StaticMethodFilters.create_char_filters("path", "Path", locals())
    StaticMethodFilters.create_integer_filters("port", "Port", locals())
    StaticMethodFilters.create_char_filters("query", "Query Parameters", locals())
    StaticMethodFilters.create_char_filters("fragment", "Fragment", locals())
    host = CharFilter(
        field_name="host",
        lookup_expr="iexact",
        help_text="Host: Exact Match",
    )
    StaticMethodFilters.create_ordering_filters(
        locals(),
        (
            "id",
            "protocol",
            "host",
            "user_info",
            "path",
            "port",
            "query",
            "fragment",
            "created_at",
            "updated_at",
        ),
    )
