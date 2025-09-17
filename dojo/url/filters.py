import logging

from django.forms import HiddenInput
from django_filters import (
    NumberFilter,
)

from dojo.api_helpers.filters import StaticMethodFilters

# from tagulous.forms import TagWidget
# import tagulous
from dojo.authorization.roles_permissions import Permissions
from dojo.location.queries import get_authorized_locations
from dojo.location.status import FindingLocationStatus, ProductLocationStatus

logger = logging.getLogger(__name__)

BOOLEAN_CHOICES = (("false", "No"), ("true", "Yes"))
EARLIEST_FINDING = None


class URLFilter(StaticMethodFilters):
    StaticMethodFilters.create_char_filters("url__protocol", "Protocol", locals())
    StaticMethodFilters.create_char_filters("url__user_info", "User Info", locals())
    StaticMethodFilters.create_char_filters("url__host", "Host", locals())
    StaticMethodFilters.create_char_filters("url__path", "Path", locals())
    StaticMethodFilters.create_integer_filters("url__port", "Port", locals())
    StaticMethodFilters.create_char_filters("url__query", "Query Parameters", locals())
    StaticMethodFilters.create_char_filters("url__fragment", "Fragment", locals())
    StaticMethodFilters.create_integer_filters("products__product__id", "Product ID", locals())
    StaticMethodFilters.create_choice_filters("products__status", "Product Status", ProductLocationStatus.choices, locals())
    StaticMethodFilters.create_choice_filters("findings__status", "Finding Status", FindingLocationStatus.choices, locals())
    StaticMethodFilters.create_char_filters("products__product__name", "Product Name", locals())
    StaticMethodFilters.create_char_filters("products__product__tags__name", "Product Tags", locals())
    StaticMethodFilters.create_char_filters("findings__finding__tags__name", "Finding Tags", locals())
    product = NumberFilter(field_name="products__product", widget=HiddenInput())
    StaticMethodFilters.create_ordering_filters(
        locals(),
        (
            "id",
            "url__protocol",
            "url__host",
            "url__user_info",
            "url__path",
            "url__port",
            "url__query",
            "url__fragment",
            "created_at",
            "updated_at",
        ),
    )

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_locations(Permissions.Location_View, parent)
