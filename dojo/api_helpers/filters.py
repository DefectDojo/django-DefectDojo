from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from django.utils import timezone
from django_filters import (
    BaseInFilter,
    BooleanFilter,
    CharFilter,
    DateTimeFromToRangeFilter,
    FilterSet,
    MultipleChoiceFilter,
    NumberFilter,
    OrderingFilter,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


# https://django-filter.readthedocs.io/en/stable/ref/filters.html#baseinfilter
class NumberInFilter(BaseInFilter, NumberFilter):

    """Support for searches like `id__in`."""


# https://django-filter.readthedocs.io/en/stable/ref/filters.html#baseinfilter
class CharFieldInFilter(BaseInFilter, CharFilter):

    """Support for searches like `id__in`."""

    def filter(self, qs, value):
        if not value:
            return qs
        if isinstance(value, str):
            value = [v.strip() for v in value.split(",") if v.strip()]
        return super().filter(qs, value)


class StaticMethodFilters(FilterSet):

    """Static methods to make setting new filters easier."""

    @staticmethod
    def set_class_variables(context: dict, class_vars: dict) -> None:
        """Set the contents of `class_vars` into the supplied context."""
        context.update(class_vars)

    @staticmethod
    def create_char_filters(
        field_name: str,
        help_text_header: str,
        context: dict,
    ) -> None:
        """
        Create all the filters needed for a CharFilter.

        - Exact Match
        - Not Exact Match
        - Contains
        - Not Contains
        - Starts with
        - Ends with
        """
        return StaticMethodFilters.set_class_variables(
            context,
            {
                f"{field_name}_exact": CharFilter(
                    field_name=field_name,
                    lookup_expr="iexact",
                    help_text=f"{help_text_header}: Exact Match",
                ),
                f"{field_name}_not_exact": CharFilter(
                    field_name=field_name,
                    lookup_expr="iexact",
                    help_text=f"{help_text_header}: Not Exact Match",
                    exclude=True,
                ),
                f"{field_name}_contains": CharFilter(
                    field_name=field_name,
                    lookup_expr="icontains",
                    help_text=f"{help_text_header}: Contains",
                ),
                f"{field_name}_not_contains": CharFilter(
                    field_name=field_name,
                    lookup_expr="icontains",
                    help_text=f"{help_text_header}: Not Contains",
                    exclude=True,
                ),
                f"{field_name}_starts_with": CharFilter(
                    field_name=field_name,
                    lookup_expr="istartswith",
                    help_text=f"{help_text_header}: Starts With",
                ),
                f"{field_name}_ends_with": CharFilter(
                    field_name=field_name,
                    lookup_expr="iendswith",
                    help_text=f"{help_text_header}: Ends With",
                ),
                f"{field_name}_includes": CharFieldInFilter(
                    field_name=field_name,
                    lookup_expr="in",
                    help_text=f"{help_text_header}: Included in List",
                ),
                f"{field_name}_not_includes": CharFieldInFilter(
                    field_name=field_name,
                    lookup_expr="in",
                    help_text=f"{help_text_header}: Not Included in List",
                    exclude=True,
                ),
            },
        )

    @staticmethod
    def create_integer_filters(
        field_name: str,
        help_text_header: str,
        context: dict,
    ) -> None:
        """
        Create all the filters needed for an IntegerFilter.

        - Exact Match
        - Not Exact Match
        - Greater Than or Equal to
        - Less Than or Equal to
        - ID included in the list
        - ID Not included in the list
        """
        return StaticMethodFilters.set_class_variables(
            context,
            {
                f"{field_name}_equals": NumberFilter(
                    field_name=field_name,
                    lookup_expr="exact",
                    help_text=f"{help_text_header}: Equals",
                ),
                f"{field_name}_not_equals": NumberFilter(
                    field_name=field_name,
                    lookup_expr="exact",
                    help_text=f"{help_text_header}: Not Equals",
                    exclude=True,
                ),
                f"{field_name}_greater_than_or_equal_to": NumberFilter(
                    field_name=field_name,
                    lookup_expr="gte",
                    help_text=f"{help_text_header}: Greater Than or Equal To",
                ),
                f"{field_name}_less_than_or_equal_to": NumberFilter(
                    field_name=field_name,
                    lookup_expr="lte",
                    help_text=f"{help_text_header}: Less Than or Equal To",
                ),
                f"{field_name}_includes": NumberInFilter(
                    field_name=field_name,
                    lookup_expr="in",
                    help_text=f"{help_text_header}: Included in List",
                ),
                f"{field_name}_not_includes": NumberInFilter(
                    field_name=field_name,
                    lookup_expr="in",
                    help_text=f"{help_text_header}: Not Included in List",
                    exclude=True,
                ),
            },
        )

    @staticmethod
    def create_choice_filters(
        field_name: str,
        help_text_header: str,
        choices: list[tuple[str]],
        context: dict,
    ) -> None:
        """Create a filter for requiring a single choice."""
        return StaticMethodFilters.set_class_variables(
            context,
            {
                f"{field_name}_equals": MultipleChoiceFilter(
                    field_name=field_name,
                    choices=choices,
                    help_text=f"{help_text_header}: Choice Filter",
                ),
            },
        )

    @staticmethod
    def create_datetime_filters(
        field_name: str,
        help_text_header: str,
        context: dict,
    ) -> None:
        """Create a filter for setting datetime filters."""
        return StaticMethodFilters.set_class_variables(
            context,
            {
                field_name: DateTimeFromToRangeFilter(
                    field_name=field_name,
                    help_text=f"{help_text_header}: DateTime Range Filter",
                ),
            },
        )

    @staticmethod
    def create_boolean_filters(
        field_name: str,
        help_text_header: str,
        context: dict,
    ) -> None:
        """Create a filter for boolean filters."""
        return StaticMethodFilters.set_class_variables(
            context,
            {
                field_name: BooleanFilter(
                    field_name=field_name,
                    help_text=f"{help_text_header}: True/False",
                ),
            },
        )

    @staticmethod
    def create_ordering_filters(
        context: dict,
        field_names: Iterable[str],
    ) -> None:
        """Create an ordering filter for all fields in the dict."""
        return StaticMethodFilters.set_class_variables(
            context,
            {"ordering": OrderingFilter(fields=[(field_name, field_name) for field_name in field_names])},
        )


class CommonFilters(StaticMethodFilters):

    """Helpers for FilterSets to reduce copy/past code."""

    StaticMethodFilters.create_integer_filters("id", "ID", locals())
    StaticMethodFilters.create_datetime_filters("created_at", "Created At", locals())
    StaticMethodFilters.create_datetime_filters("updated_at", "Updated At", locals())


def filter_timestamp(queryset, name, value):
    try:
        date = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return queryset

    start_datetime = timezone.make_aware(datetime.combine(date, datetime.min.time()))
    end_datetime = timezone.make_aware(datetime.combine(date + timedelta(days=1), datetime.min.time()))

    return queryset.filter(**{f"{name}__gte": start_datetime, f"{name}__lt": end_datetime})


def csv_filter(queryset, name, value):
    return queryset.filter(**{f"{name}__in": value.split(",")})


class CustomOrderingFilter(OrderingFilter):
    def __init__(self, *args, **kwargs):
        self.reverse_fields = kwargs.pop("reverse_fields", [])
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value in {None, ""}:
            return qs

        ordering = []

        for param in value:
            stripped_param = param.strip()
            raw_field = stripped_param.lstrip("-")
            reverse = raw_field in self.reverse_fields

            if reverse:
                if stripped_param.startswith("-"):
                    ordering.append(raw_field)
                else:
                    ordering.append(f"-{raw_field}")
            else:
                ordering.append(stripped_param)

        return qs.order_by(*ordering)
