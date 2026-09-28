"""
Tag filters that match only the tag sets the caller may read.

A Location row is shared by every product referencing it and so is its tag set, so a filter
that joins the tag relation directly matches through other products' tags. That turns any
substring lookup into a character-by-character oracle over a tag set the caller cannot read
in a response body. Every filter here runs its lookup inside
``dojo.location.queries.readable_tag_match`` instead, which is the same predicate the
serializers use, so a filter never matches on a value the body would withhold.
"""
from django_filters import BooleanFilter, CharFilter
from django_filters.constants import EMPTY_VALUES

from dojo.api_helpers.filters import CharFieldInFilter, StaticMethodFilters
from dojo.location.queries import readable_tag_match


class _ReadableTagFilterMixin:
    location_field = "pk"

    def __init__(self, *args, location_field="pk", **kwargs):
        self.location_field = location_field
        super().__init__(*args, **kwargs)

    def _match(self, **lookups):
        return readable_tag_match(self.location_field, **lookups)

    def _apply(self, qs, match):
        return qs.exclude(match) if self.exclude else qs.filter(match)


class ReadableTagFilter(_ReadableTagFilterMixin, CharFilter):
    def filter(self, qs, value):
        if value in EMPTY_VALUES:
            return qs
        return self._apply(qs, self._match(**{f"tags__name__{self.lookup_expr}": value}))


class ReadableTagInFilter(_ReadableTagFilterMixin, CharFieldInFilter):
    def filter(self, qs, value):
        names = _names(value)
        if not names:
            return qs
        return self._apply(qs, self._match(tags__name__in=names))


class ReadableTagANDFilter(ReadableTagInFilter):
    def filter(self, qs, value):
        for name in _names(value):
            qs = qs.filter(self._match(tags__name=name))
        return qs


class ReadableHasTagsFilter(_ReadableTagFilterMixin, BooleanFilter):
    def filter(self, qs, value):
        if value in EMPTY_VALUES:
            return qs
        match = self._match(tags__isnull=False)
        return qs.filter(match) if value else qs.exclude(match)


def _names(value):
    if not value:
        return []
    if isinstance(value, str):
        value = value.split(",")
    return [name.strip() for name in value if name and name.strip()]


def create_readable_tag_filters(help_text_header, context, *, location_field="pk"):
    """Drop-in replacement for ``create_char_filters`` on a Location tag relation."""
    def char(lookup, label, *, exclude=False):
        return ReadableTagFilter(
            lookup_expr=lookup,
            exclude=exclude,
            location_field=location_field,
            help_text=f"{help_text_header}: {label}",
        )

    def in_list(label, *, exclude=False):
        return ReadableTagInFilter(
            exclude=exclude,
            location_field=location_field,
            help_text=f"{help_text_header}: {label}",
        )

    return StaticMethodFilters.set_class_variables(
        context,
        {
            "tags__name_exact": char("iexact", "Exact Match"),
            "tags__name_not_exact": char("iexact", "Not Exact Match", exclude=True),
            "tags__name_contains": char("icontains", "Contains"),
            "tags__name_not_contains": char("icontains", "Not Contains", exclude=True),
            "tags__name_starts_with": char("istartswith", "Starts With"),
            "tags__name_ends_with": char("iendswith", "Ends With"),
            "tags__name_includes": in_list("Included in List"),
            "tags__name_not_includes": in_list("Not Included in List", exclude=True),
        },
    )
