"""
The serializers a plugin registers for a prefetched model (see ``_Prefetcher.serializer_overrides``).

Kept outside the ``prefetch`` package (whose ``__init__`` imports the prefetcher) and free of imports from dojo, so an
``AppConfig.ready()`` can register without importing the serializer modules the prefetcher imports.
"""

from django.utils.module_loading import import_string

# Serializers a plugin registers for a model, used in place of the one found in SERIALIZER_DEFS_MODULE: a class, or
# its dotted path until first use. Mutated in place (mirrors dojo.authorization.query_filters._AUTH_FILTER_REGISTRY).
_REGISTERED_SERIALIZERS: dict[type, type | str] = {}


def register_prefetch_serializer(model, serializer, *, override=False):
    """
    Register the serializer a prefetched ``model`` is rendered with.

    ``serializer`` is the class or its dotted path. A path is imported the first time the model is prefetched, so an
    ``AppConfig.ready()`` can register a serializer without importing its module (and what that module imports)
    before the app has finished patching. Without ``override`` an existing entry is kept; a plugin replacing one
    passes ``override=True``, so the wiring does not depend on which ``ready()`` runs first. The serializer is given
    every object of the model the response prefetches as ``context["prefetched_objects"]``, so it can read what it
    needs for all of them at once.
    """
    if model in _REGISTERED_SERIALIZERS and not override:
        return
    _REGISTERED_SERIALIZERS[model] = serializer


def registered_serializer(model):
    """The serializer registered for ``model``, its dotted path imported once, or None."""
    serializer = _REGISTERED_SERIALIZERS.get(model)
    if isinstance(serializer, str):
        serializer = _REGISTERED_SERIALIZERS[model] = import_string(serializer)
    return serializer
