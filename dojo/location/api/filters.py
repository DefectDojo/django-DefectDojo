from __future__ import annotations

from django_filters import NumberFilter

from dojo.api_helpers.filters import CommonFilters, StaticMethodFilters
from dojo.location.status import FindingLocationStatus, ProductLocationStatus


class AbstractedLocationFilter(StaticMethodFilters):
    StaticMethodFilters.create_integer_filters("id", "ID", locals())
    StaticMethodFilters.create_char_filters("location__tags__name", "Tags", locals())
    StaticMethodFilters.create_char_filters("location__created_at", "Created At", locals())
    StaticMethodFilters.create_char_filters("location__updated_at", "Updated At", locals())
    StaticMethodFilters.create_integer_filters("location__products__product", "Product ID", locals())
    StaticMethodFilters.create_integer_filters("location__findings__finding", "Finding ID", locals())

    product = NumberFilter(
        field_name="location__products__product",
        lookup_expr="exact",
        help_text="Product ID: Equals",
    )


class LocationFilter(CommonFilters):

    """Conglomerate of all Location filters."""

    # ordering (the order of the fields is enforced)
    CommonFilters.create_char_filters("location_type", "Location Type", locals())
    CommonFilters.create_char_filters("location_value", "Location Value", locals())
    CommonFilters.create_char_filters("tags__name", "Tags", locals())
    CommonFilters.create_integer_filters("products__product", "Product ID", locals())
    CommonFilters.create_integer_filters("findings__finding", "Finding ID", locals())
    CommonFilters.create_ordering_filters(
        locals(),
        (
            "id",
            "location_type",
            "location_value",
            "created_at",
            "updated_at",
        ),
    )


class LocationProductReferenceFilter(CommonFilters):
    CommonFilters.create_integer_filters("location", "Location", locals())
    CommonFilters.create_integer_filters("product", "Product", locals())
    CommonFilters.create_char_filters("product__name", "Product Name", locals())
    CommonFilters.create_choice_filters("status", "Status", ProductLocationStatus.choices, locals())
    CommonFilters.create_char_filters("location_type", "Location Type", locals())
    CommonFilters.create_char_filters("location_value", "Location Value", locals())
    CommonFilters.create_ordering_filters(
        locals(),
        (
            "id",
            "location_type",
            "location_value",
            "product",
            "product__name",
            "status",
            "created_at",
            "updated_at",
        ),
    )


class LocationFindingReferenceFilter(CommonFilters):
    CommonFilters.create_integer_filters("location", "Location", locals())
    CommonFilters.create_integer_filters("finding", "Finding", locals())
    CommonFilters.create_char_filters("finding__severity", "Finding Severity", locals())
    CommonFilters.create_choice_filters("status", "Status", FindingLocationStatus.choices, locals())
    CommonFilters.create_char_filters("location_type", "Location Type", locals())
    CommonFilters.create_char_filters("location_value", "Location Value", locals())
    CommonFilters.create_ordering_filters(
        locals(),
        (
            "id",
            "location_type",
            "location_value",
            "finding",
            "finding__severity",
            "status",
            "created_at",
            "updated_at",
        ),
    )
