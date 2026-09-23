import logging

from django.core.validators import EMPTY_VALUES
from django.db.models import Exists, OuterRef
from django.forms import HiddenInput
from django_filters import (
    NumberFilter,
)

from dojo.api_helpers.filters import StaticMethodFilters
from dojo.authorization.roles_permissions import Permissions

# from tagulous.forms import TagWidget
# import tagulous
from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.location.queries import get_authorized_locations
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.product.queries import get_authorized_products

logger = logging.getLogger(__name__)

BOOLEAN_CHOICES = (("false", "No"), ("true", "Yes"))
EARLIEST_FINDING = None

# Relations that leave the Location and reach another product's rows, mapped to the
# reference model that carries them and the path from that model to its product.
OUTWARD_RELATIONS = {
    "products": (LocationProductReference, "product__in"),
    "findings": (LocationFindingReference, "finding__test__engagement__product__in"),
}


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
            "active_findings",
        ),
    )

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def filter_queryset(self, queryset):
        """
        Match each predicate against the caller's own references only.

        A Location is shared by every product that references it, so a predicate that
        joins outward can be satisfied by a reference the caller cannot see. Narrowing
        the result afterwards does not help: that is a second, independent join, and the
        row still qualifies through its own product.
        """
        authorized_products = get_authorized_products(Permissions.Product_View, self.user)
        for name, value in self.form.cleaned_data.items():
            declared = self.filters[name]
            relation, _, remainder = (declared.field_name or "").partition("__")
            outward = OUTWARD_RELATIONS.get(relation)
            if outward is None or value in EMPTY_VALUES:
                queryset = declared.filter(queryset, value)
                continue
            reference_model, product_path = outward
            lookup = "in" if isinstance(value, list | tuple) else declared.lookup_expr
            matching_references = reference_model.objects.filter(
                **{
                    "location": OuterRef("pk"),
                    f"{remainder}__{lookup}" if remainder else lookup: value,
                    product_path: authorized_products,
                },
            )
            queryset = (
                queryset.exclude(Exists(matching_references))
                if declared.exclude
                else queryset.filter(Exists(matching_references))
            )
        return queryset

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_locations("view", parent)
