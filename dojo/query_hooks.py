"""
Default-queryset hooks for plugins.

A model whose ``objects`` manager is a ``HookedManager`` (or ``HookedBaseManager``)
applies every filter registered for its label, in registration order, to the
queryset it returns. With nothing registered the queryset is unchanged, so the
open source behaviour is exactly that of a plain manager.

``objects`` is declared first on those models, so it is also ``_default_manager``:
the filters reach reverse relations, ``get()`` and uniqueness checks as well. Each
model also carries an ``unfiltered`` manager, the explicit way to bypass them.
``_base_manager`` stays a plain manager, so forward foreign key access and the
deletion collector are never filtered.
"""

from django.db.models import Manager

from dojo.base_models.base import BaseManager

_DEFAULT_QUERYSET_FILTERS = {}


def register_default_queryset_filter(model_label, key, func):
    # Keyed so a repeated ready() (tests, autoreload) replaces rather than stacks.
    _DEFAULT_QUERYSET_FILTERS.setdefault(model_label.lower(), {})[key] = func


def get_default_queryset_filters(model_label):
    return tuple(_DEFAULT_QUERYSET_FILTERS.get(model_label.lower(), {}).values())


def apply_default_queryset_filters(model, queryset):
    for func in get_default_queryset_filters(model._meta.label):
        queryset = func(queryset)
    return queryset


class HookedManagerMixin:
    def get_queryset(self):
        return apply_default_queryset_filters(self.model, super().get_queryset())


class HookedManager(HookedManagerMixin, Manager):
    pass


class HookedBaseManager(HookedManagerMixin, BaseManager):
    pass


class UnfilteredManager(Manager):

    """A plain manager, declared as ``unfiltered`` beside a hooked ``objects``: the explicit bypass."""
