"""
RBAC registry for the ``?prefetch=`` path.

The prefetch mixins resolve a query-string field name through ``getattr`` on a
model instance, find a serializer for the resolved related model, and return
the serialized representation. This module allows us to specify authorization
checks on the related objects when serializing.

``_Prefetcher`` filters every resolved related object through the registered
queryset before serializing it. If no policy is registered for a model, the
field is omitted from the response.
"""

from collections.abc import Callable

from django.db.models import Model, Q, QuerySet

from dojo.authorization.authorization import user_has_configuration_permission
from dojo.models import Engagement, Finding, Notes, Test

_REGISTRY: dict[type[Model], Callable[[object], QuerySet]] = {}


def discard_user(func):
    """
    Adapter for auth helpers that don't accept a ``user`` parameter --
    wraps them so they can be passed to ``register()`` like any other policy.
    """

    def wrapper(*args, user, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def register(model: type[Model], func: Callable, *args, **kwargs) -> None:
    """Register a policy for ``model``. At lookup, ``func`` is invoked as ``func(*args, user=<requesting user>, **kwargs)``."""

    def policy(user):
        return func(*args, user=user, **kwargs)

    _REGISTRY[model] = policy


def get_authorized_queryset(model: type[Model], user) -> QuerySet | None:
    """
    Return the queryset of ``model`` instances visible to ``user``.

    Returns ``None`` when no policy has been registered. ``_Prefetcher``
    treats ``None`` as "deny" and omits the field from the response.
    """
    if policy := _REGISTRY.get(model):
        return policy(user)
    return None


def superuser_only(model: type[Model], user) -> QuerySet:
    """
    Policy for models whose top-level ViewSet enforces ``IsSuperUser``
    (strict ``request.user.is_superuser`` check). Only superusers pass.
    """
    if user is not None and getattr(user, "is_superuser", False):
        return model.objects.all()
    return model.objects.none()


def django_view_perm(model: type[Model], user) -> QuerySet:
    """
    Policy for models whose top-level ViewSet gates on DRF's ``DjangoModelPermissions``.

    Passes all superusers and any user holding ``<app_label>.view_<model_name>``.
    """
    if user is None:
        return model.objects.none()
    perm = f"{model._meta.app_label}.view_{model._meta.model_name}"
    if user.has_perm(perm):
        return model.objects.all()
    return model.objects.none()


def dojo_view_perm(model: type[Model], user) -> QuerySet:
    """
    Policy for models whose top-level ViewSet gates on a DefectDojo
    ``BaseDjangoModelPermission`` subclass that requires GET=view.

    Passes all superusers and staff users and any user holding ``<app_label>.view_<model_name>``.
    """
    if user is None:
        return model.objects.none()
    perm = f"{model._meta.app_label}.view_{model._meta.model_name}"
    if user_has_configuration_permission(user, perm):
        return model.objects.all()
    return model.objects.none()


def authenticated_only(model: type[Model], user) -> QuerySet:
    """Policy for models whose top-level ViewSet is reachable by any authenticated user."""
    if user is not None and getattr(user, "is_authenticated", False):
        return model.objects.all()
    return model.objects.none()


def children_via_parent(child_model, parent_model, parent_field, *, user) -> QuerySet:
    """
    Authorize ``child_model`` by deferring to the policy registered for
    ``parent_model`` -- the child is visible iff the parent it points to via
    ``parent_field`` is visible. Used for models that don't have their own
    ``get_authorized_*`` helper but logically inherit authorization from a
    parent (e.g. ``BurpRawRequestResponse`` -> ``Finding`` via ``finding``).
    """
    if (parent_qs := get_authorized_queryset(parent_model, user)) is not None:
        return child_model.objects.filter(**{f"{parent_field}__in": parent_qs})
    return child_model.objects.none()


def notes_policy(user) -> QuerySet:
    """
    Authorization for the ``Notes`` model.

    Allows note viewership as follows:
        * superuser: every note
        * anyone else: a note is visible iff
            (its attached Finding / Test / Engagement is visible to ``user``)
            AND (the note is non-private OR ``user`` authored it).
    """
    if user is None:
        return Notes.objects.none()
    if getattr(user, "is_superuser", False):
        return Notes.objects.all()

    # Helper method to avoid unnecessary queryset fetching
    def _qs_or_none(model, u):
        qs = get_authorized_queryset(model, u)
        return model.objects.none() if qs is None else qs

    finding_qs = _qs_or_none(Finding, user)
    test_qs = _qs_or_none(Test, user)
    engagement_qs = _qs_or_none(Engagement, user)

    parent_visible = Q(finding__in=finding_qs) | Q(test__in=test_qs) | Q(engagement__in=engagement_qs)
    return Notes.objects.filter(
        parent_visible,
        Q(private=False) | Q(author=user),
    ).distinct()
