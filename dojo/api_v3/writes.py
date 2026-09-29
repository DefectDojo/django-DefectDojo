"""
Write-payload seam for API v3 (I4 + I5).

Read schemas are already extensible: a downstream distribution subclasses ``FindingSlim`` and the
kernel serializes, plans and documents the added fields with no further help. Write schemas were
not, because the route bodies hand the whole validated payload to a service that applies it to the
OS model -- so an added field would either be dropped or raise.

``split_extras`` is the missing half. A route partitions the payload into the fields the OS service
understands and everything the subclass added, applies the first through the service unchanged, and
hands the second to an ``on_write`` callback after the write succeeds. The service therefore never
sees a field it does not own, and the downstream never has to re-implement the route to persist its
own columns.

The partition is computed against the **OS base schema**, not the schema the route was built with,
so it stays correct however deep the subclass chain goes.
"""
from __future__ import annotations

from typing import Any

__all__ = ["OnWrite", "bind_payload", "split_extras"]


def bind_payload(schema: type):
    """
    Bind a runtime-selected body schema to a route's ``payload`` parameter.

    Needed because the route modules use ``from __future__ import annotations``, so
    ``def route(request, payload: create_schema)`` stores the literal string ``"create_schema"``.
    Pydantic then tries to resolve that against module globals, where it does not exist -- it is a
    parameter of the enclosing factory -- and fails with
    ``PydanticUserError: QueryParams is not fully defined``.

    Writing the resolved class straight into ``__annotations__`` sidesteps the lookup:
    ``get_type_hints`` passes a non-string annotation through untouched. Applied *below*
    ``@router.<verb>`` so the annotation is already bound when ninja introspects the signature::

        @router.post("/findings", response=detail_schema)
        @bind_payload(create_schema)
        def create_finding_route(request: HttpRequest, payload):
            ...
    """
    def decorator(func):
        func.__annotations__["payload"] = schema
        return func
    return decorator


# Called after a successful create/update with the fields the base schema did not declare:
#   on_write(instance, extras, user=<Dojo_User>, created=<bool>) -> None
# Side-effecting only; the response is re-read from the database afterwards, so a callback that
# mutates a companion row is reflected without returning anything.
OnWrite = "Callable[..., None]"


def split_extras(data: dict[str, Any], base_schema: type) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Partition ``data`` into ``(base, extras)`` against ``base_schema``'s declared fields.

    ``base`` is what the OS service is given; ``extras`` is what a subclass added and is passed to
    ``on_write``. Computed from the base schema rather than the route's configured schema so that
    subclassing at any depth still routes each field to the right side.
    """
    known = set(base_schema.model_fields)
    base = {key: value for key, value in data.items() if key in known}
    extras = {key: value for key, value in data.items() if key not in known}
    return base, extras
