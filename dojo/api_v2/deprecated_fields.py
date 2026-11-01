"""
Field-level deprecation notices for the /api/v2 viewsets.

A viewset that serves a field which is going away names it in ``deprecated_fields`` (field name to
deprecation key, see ``DeprecatedFieldsMixin``). The response to a request that writes the field,
filters by it or orders by it says so in ``X-Deprecated-Fields``. A read cannot be told apart, since
the field is in every body, so the OpenAPI schema marks the field and its filters deprecated too.
Both read the declaration by key, and a key without an active declaration produces neither.
"""

from collections.abc import Mapping

from rest_framework.exceptions import ParseError, UnsupportedMediaType

from dojo.deprecations import Deprecation, get_deprecation

ORDERING_PARAMETERS = ("o", "ordering")
WRITE_METHODS = ("POST", "PUT", "PATCH")


def active_fields(deprecated_fields: Mapping[str, str]) -> dict[str, Deprecation]:
    """The fields of ``deprecated_fields`` whose declaration is active, with that declaration."""
    active = {}
    for name, key in deprecated_fields.items():
        notice = get_deprecation(key)
        if notice is not None and not notice.removed:
            active[name] = notice
    return active


def fields_used_by(request, names) -> set[str]:
    """Which of ``names`` the request writes, filters by (``name`` or ``name__<lookup>``) or orders by."""
    names = set(names)
    used = set()
    params = request.query_params
    for parameter in params:
        if parameter.split("__", 1)[0] in names:
            used.add(parameter.split("__", 1)[0])
    for parameter in ORDERING_PARAMETERS:
        for value in params.getlist(parameter):
            used |= names & {term.strip().lstrip("-") for term in value.split(",")}
    if request.method in WRITE_METHODS:
        # The view may have refused the body already; the notice never raises in its place.
        try:
            data = request.data
        except (ParseError, UnsupportedMediaType):
            data = None
        for row in data if isinstance(data, list) else [data]:
            if isinstance(row, Mapping):
                used |= names & set(row)
    return used


def _schema_refs(node, refs):
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            refs.add(ref.rsplit("/", 1)[-1])
        for value in node.values():
            _schema_refs(value, refs)
    elif isinstance(node, list):
        for value in node:
            _schema_refs(value, refs)
    return refs


def deprecated_fields_postprocessing_hook(result, generator, request, public):
    """
    Mark each active deprecated field ``deprecated`` in the schema of every operation that serves it.

    The field is marked on the request and response components the operation names (following a
    paginated list to its items), and on the operation's filter parameters for that field.
    """
    schemas = result.get("components", {}).get("schemas", {})
    paths = result.get("paths", {})
    for path, _pattern, method, view in generator._get_paths_and_endpoints():
        fields = active_fields(getattr(view, "deprecated_fields", {}))
        operation = paths.get(path, {}).get(method.lower())
        if not fields or not operation:
            continue
        for parameter in operation.get("parameters", []):
            if parameter.get("name", "").split("__", 1)[0] in fields:
                parameter["deprecated"] = True
        components = _schema_refs({"body": operation.get("requestBody"), "responses": operation.get("responses")}, set())
        # A paginated list names its row component only inside the wrapper.
        for name in [name for name in components if name.startswith("Paginated")]:
            _schema_refs(schemas.get(name, {}), components)
        for name in components:
            properties = schemas.get(name, {}).get("properties", {})
            for field in fields:
                if field in properties:
                    properties[field]["deprecated"] = True
    return result
