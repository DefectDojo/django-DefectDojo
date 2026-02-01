import logging

from django.core.exceptions import ValidationError
from django.db.models import Q

from dojo.location.models import AbstractLocation
from dojo.url.models import URL
from dojo.url.validators import DEFAULT_PORTS

logger = logging.getLogger(__name__)


def save_location(unsaved_location: AbstractLocation) -> AbstractLocation:
    # Only support URLs at this time
    if isinstance(unsaved_location, URL):
        return URL.get_or_create_from_object(unsaved_location)
    error_message = f"Unsupported location type {type(unsaved_location)}"
    raise ValidationError(error_message)


def save_locations_to_add(locations_to_add: list[AbstractLocation]) -> list[AbstractLocation]:
    return [save_location(unsaved_location) for unsaved_location in locations_to_add]


def validate_locations_to_add(locations_to_add: str) -> tuple[list[AbstractLocation], list[ValidationError]]:
    errors = []
    locations = []
    location_strings = locations_to_add.split()
    # For now, we only support URL location types
    for location_string in location_strings:
        try:
            locations.append(URL.from_value(location_string))
        except ValidationError as ves:
            errors.extend(ValidationError(f"Invalid location {location_string}: {ve}") for ve in ves)

    return locations, errors


# This code blatantly rips off dojo.endpoint.utils.endpoint_filter()
def url_filter(**kwargs):
    qs = URL.objects.all()

    qs = qs.filter(protocol__iexact=kwargs["protocol"]) if kwargs.get("protocol") else qs.filter(protocol="")

    qs = qs.filter(user_info__exact=kwargs["user_info"]) if kwargs.get("user_info") else qs.filter(user_info="")

    qs = qs.filter(host__iexact=kwargs["host"]) if kwargs.get("host") else qs.filter(host="")

    if kwargs.get("port"):
        if (kwargs.get("protocol")) and \
                (kwargs["protocol"].lower() in DEFAULT_PORTS) and \
                (DEFAULT_PORTS[kwargs["protocol"].lower()] == kwargs["port"]):
            qs = qs.filter(Q(port__isnull=True) | Q(port__exact=DEFAULT_PORTS[kwargs["protocol"].lower()]))
        else:
            qs = qs.filter(port__exact=kwargs["port"])
    elif (kwargs.get("protocol")) and (kwargs["protocol"].lower() in DEFAULT_PORTS):
        qs = qs.filter(Q(port__isnull=True) | Q(port__exact=DEFAULT_PORTS[kwargs["protocol"].lower()]))
    else:
        qs = qs.filter(port__isnull=True)

    qs = qs.filter(path__exact=kwargs["path"]) if kwargs.get("path") else qs.filter(path="")

    qs = qs.filter(query__exact=kwargs["query"]) if kwargs.get("query") else qs.filter(query="")

    return qs.filter(fragment__exact=kwargs["fragment"]) if kwargs.get("fragment") else qs.filter(fragment="")


# This code blatantly rips off dojo.endpoint.utils.endpoint_get_or_create()
def url_get_or_create(**kwargs):
    # This code looks a bit ugly/complicated.
    # But this method is called so frequently that we need to optimize it.
    # It executes at most one SELECT and one optional INSERT.
    qs = url_filter(**kwargs)
    # Fetch up to two matches in a single round-trip. This covers
    # the common cases efficiently: zero (create) or one (reuse).
    matches = list(qs.order_by("id")[:2])
    if not matches:
        # Most common case: nothing exists yet
        return URL.get_or_create_from_values(**kwargs), True
    if len(matches) == 1:
        # Common case: exactly one existing URL
        return matches[0], False
    # Get the oldest URL first, and return that instead
    # a datetime is not captured on the URL model, so ID
    # will have to work here instead
    return matches[0], False
