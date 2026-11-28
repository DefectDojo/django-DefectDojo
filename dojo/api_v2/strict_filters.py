"""
Reject list query parameters that no filter declares.

django-filter ignores a query key it does not know, so ``?not_a_filter=x`` (or a typo in a real
filter name) used to return every row with a 200, and automation that mistyped a filter acted on far
more data than intended. :class:`StrictDjangoFilterBackend` is a drop-in ``DjangoFilterBackend``
that, on a list request, compares the query keys with the keys the view understands and answers
400 naming the unknown ones.

A key is known when it is one of:

* a filter the view's FilterSet declares, including generated lookup variants (``id__in``,
  ``title__icontains``) and the suffixed keys of a range widget (``date_after``, ``cvssv3_score_min``);
* a reserved parameter (:data:`RESERVED_QUERY_PARAMS`: pagination, ordering, prefetch, response
  shaping and the format override, plus any a plugin adds with :func:`register_reserved_query_params`);
* a parameter of the view's paginator or of another filter backend on the view (``search``,
  ``ordering``, ``page``, ``page_size``...);
* listed in ``extra_query_params`` on the view or any class it inherits from, for a view (or a
  mixin) that reads a parameter by hand.

``DD_API_UNKNOWN_QUERY_PARAMS`` (``settings.API_UNKNOWN_QUERY_PARAMS``) picks the behaviour:
``enforce`` (the default) answers 400, ``warn`` serves the request and names the keys in the
``X-DefectDojo-Unknown-Query-Params`` response header and a log line, and ``off`` ignores them as
django-filter always did. A detail route is never checked: it returns one object whatever the
query string says.
"""

import logging

from django.conf import settings
from django.forms import MultiWidget
from django.utils.translation import gettext as _
from django_filters import utils
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.exceptions import ValidationError
from rest_framework.settings import api_settings

logger = logging.getLogger(__name__)

UNKNOWN_QUERY_PARAMS_ENFORCE = "enforce"
UNKNOWN_QUERY_PARAMS_WARN = "warn"
UNKNOWN_QUERY_PARAMS_OFF = "off"
UNKNOWN_QUERY_PARAMS_MODES = (UNKNOWN_QUERY_PARAMS_ENFORCE, UNKNOWN_QUERY_PARAMS_WARN, UNKNOWN_QUERY_PARAMS_OFF)

UNKNOWN_QUERY_PARAMS_HEADER = "X-DefectDojo-Unknown-Query-Params"

# Parameters every list accepts whether or not a filter declares them.
RESERVED_QUERY_PARAMS = frozenset({
    "limit",
    "offset",
    "o",
    "ordering",
    "prefetch",
    "related_fields",
    "response_fields",
    api_settings.URL_FORMAT_OVERRIDE or "format",
})

# Parameters a plugin reads on every request (a middleware, a client interceptor): see
# register_reserved_query_params.
_registered_query_params: set[str] = set()


def register_reserved_query_params(*names):
    """Accept ``names`` on every list, for a parameter something other than the view reads."""
    _registered_query_params.update(names)


def reserved_query_params():
    return RESERVED_QUERY_PARAMS | _registered_query_params


# The attributes DRF's paginators and filter backends name their query parameters with.
_PARAM_ATTRIBUTES = (
    "limit_query_param",
    "offset_query_param",
    "page_query_param",
    "page_size_query_param",
    "cursor_query_param",
    "search_param",
    "ordering_param",
)


def unknown_query_params_mode():
    mode = getattr(settings, "API_UNKNOWN_QUERY_PARAMS", UNKNOWN_QUERY_PARAMS_ENFORCE)
    if mode not in UNKNOWN_QUERY_PARAMS_MODES:
        return UNKNOWN_QUERY_PARAMS_ENFORCE
    return mode


def _component_params(component):
    names = set()
    for attribute in _PARAM_ATTRIBUTES:
        value = getattr(component, attribute, None)
        if isinstance(value, str) and value:
            names.add(value)
    return names


def filterset_query_params(filterset):
    """Every query key a FilterSet instance reads, widget suffixes included."""
    names = set(filterset.filters)
    # A FilterSet that reads a parameter from its data by hand (not through a filter) names it here.
    names.update(getattr(filterset, "extra_query_params", ()))
    for name, field in filterset.form.fields.items():
        widget = field.widget
        suffixes = getattr(widget, "suffixes", None)
        if suffixes is not None:
            # django-filter's SuffixedMultiWidget: ``<name>_<suffix>``, or the bare name for "".
            names.update(f"{name}_{suffix}" if suffix else name for suffix in suffixes)
        elif isinstance(widget, MultiWidget):
            names.update(f"{name}{widget_name}" for widget_name in widget.widgets_names)
    return names


def view_query_params(view):
    """The query keys a view understands apart from its FilterSet's."""
    names = set(reserved_query_params())
    paginator = getattr(view, "paginator", None)
    if paginator is not None:
        names |= _component_params(paginator)
    for backend in getattr(view, "filter_backends", ()):
        names |= _component_params(backend)
    # Every class's own declaration counts, so a mixin and the view that uses it each name theirs.
    for klass in type(view).__mro__:
        names.update(vars(klass).get("extra_query_params", ()))
    names.update(vars(view).get("extra_query_params", ()))
    return names


def known_query_params(view, filterset):
    """Every query key a list served by ``view`` with ``filterset`` (or None) understands."""
    names = view_query_params(view)
    if filterset is not None:
        names |= filterset_query_params(filterset)
    return names


def _is_detail_request(view):
    kwargs = getattr(view, "kwargs", None) or {}
    lookup = getattr(view, "lookup_url_kwarg", None) or getattr(view, "lookup_field", None)
    return bool(lookup) and lookup in kwargs


def check_unknown_query_params(request, view, known):
    """
    Apply the configured mode to the query keys of ``request`` that are not known.

    ``known`` is the set of known keys, or a callable returning it: it is only built when the mode
    is not ``off`` and the request carries a key that is not reserved.
    """
    mode = unknown_query_params_mode()
    if mode == UNKNOWN_QUERY_PARAMS_OFF:
        return
    reserved = reserved_query_params()
    candidates = [key for key in request.query_params if key not in reserved]
    if not candidates:
        return
    if callable(known):
        known = known()
    unknown = sorted(key for key in candidates if key not in known)
    if not unknown:
        return
    if mode == UNKNOWN_QUERY_PARAMS_WARN:
        logger.warning("Unknown query parameter(s) ignored on %s: %s", request.path, ", ".join(unknown))
        headers = getattr(view, "headers", None)
        if isinstance(headers, dict):
            headers[UNKNOWN_QUERY_PARAMS_HEADER] = ",".join(unknown)
        return
    message = _("Unknown query parameter. It is not a filter on this list.")
    raise ValidationError({key: [message] for key in unknown})


class StrictDjangoFilterBackend(DjangoFilterBackend):

    """``DjangoFilterBackend`` that rejects a list request's unknown query keys (see the module docstring)."""

    def filter_queryset(self, request, queryset, view):
        filterset = self.get_filterset(request, queryset, view)
        if not _is_detail_request(view):
            check_unknown_query_params(request, view, lambda: known_query_params(view, filterset))
        if filterset is None:
            return queryset
        if not filterset.is_valid() and self.raise_exception:
            raise utils.translate_validation(filterset.errors)
        return filterset.qs
