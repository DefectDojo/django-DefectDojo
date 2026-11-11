import logging
from functools import reduce
from operator import or_

from django.db.models import Q, Subquery
from django.db.models.deletion import get_candidate_relations_to_delete
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import DjangoModelPermissions

from dojo.api_v2 import serializers
from dojo.models import Endpoint

logger = logging.getLogger(__name__)

# The most rows one delete_preview request renders, whatever limit it asks for. Rendering is
# Python work (one instance and one str() per row) that no SQL statement timeout can stop.
DELETE_PREVIEW_MAX_PAGE_SIZE = 250

# A CASCADE chain deeper than this is a cycle in the data, not a real hierarchy.
DELETE_PREVIEW_MAX_DEPTH = 32


def delete_preview_querysets(obj):
    """
    One queryset per model a delete of ``obj`` cascades to, in the order the walk first reaches it.

    It follows the relations Django's deletion Collector follows (``get_candidate_relations_to_delete``,
    hidden relations and many-to-many through rows included, plus each collected row's multi-table
    parent rows; no model has a generic relation, which the Collector would also follow, see
    ``DeletePreviewBoundTest.test_no_model_has_a_generic_relation``) but builds nested subqueries instead of
    loading the rows, so its cost does not grow with the number of objects. The pk subqueries drop
    ``Meta.ordering``: sorted inside an ``IN (SELECT ...)`` they make Postgres sort every parent row on
    every step. A model reached along several paths gets one queryset over all of them, so a row is
    listed once. A path with no rows is not walked further.
    """
    model = type(obj)
    filters = {}

    def add_parents(child_model, pks):
        # The Collector also deletes a collected row's multi-table parent rows (not their other relations).
        for parent, ptr in child_model._meta.concrete_model._meta.parents.items():
            if ptr is None:
                continue
            parent_pks = child_model._base_manager.filter(pk__in=Subquery(pks)).values(ptr.attname).order_by()
            filters.setdefault(parent, []).append(Q(pk__in=Subquery(parent_pks)))
            add_parents(parent, parent_pks)

    def walk(from_model, pks, depth):
        if depth > DELETE_PREVIEW_MAX_DEPTH:
            logger.warning("delete_preview: cascade from %s deeper than %d, stopping", model.__name__, depth)
            return
        for relation in get_candidate_relations_to_delete(from_model._meta):
            field = relation.field
            # django-polymorphic wraps on_delete in a guard that keeps the real handler on .action.
            on_delete = getattr(field.remote_field.on_delete, "action", field.remote_field.on_delete)
            if getattr(on_delete, "__name__", None) != "CASCADE":
                continue
            related_model = relation.related_model
            condition = Q(**{f"{field.name}__in": Subquery(pks)})
            related = related_model._base_manager.filter(condition)
            if not related.exists():
                continue
            filters.setdefault(related_model, []).append(condition)
            related_pks = related.values("pk").order_by()
            add_parents(related_model, related_pks)
            walk(related_model, related_pks, depth + 1)

    root_pks = model._base_manager.filter(pk=obj.pk).values("pk").order_by()
    add_parents(model, root_pks)
    walk(model, root_pks, 0)

    querysets = []
    for related_model, conditions in filters.items():
        queryset = related_model._base_manager.filter(reduce(or_, conditions))
        if hasattr(queryset, "non_polymorphic"):
            # As PolymorphicGuard hands them to the Collector: an Answer row is listed as an Answer, not
            # again as the TextAnswer its own row already lists.
            queryset = queryset.non_polymorphic()
        if related_model is model:
            queryset = queryset.exclude(pk=obj.pk)
        querysets.append(queryset.order_by("pk"))
    return querysets


class DeletePreviewRows:

    """
    The rows of a delete preview as a sequence a paginator can slice.

    The root object comes first, then each cascaded model's rows by primary key. Counting runs one
    COUNT per model, and a slice loads and renders only the rows inside it.
    """

    def __init__(self, obj):
        self.obj = obj
        self._parts = None

    def _counted_parts(self):
        if self._parts is None:
            self._parts = [(None, 1)] + [(queryset, queryset.count()) for queryset in delete_preview_querysets(self.obj)]
        return self._parts

    def count(self):
        return sum(n for _, n in self._counted_parts())

    def __len__(self):
        return self.count()

    def __getitem__(self, index):
        # Paginators only slice.
        start, stop, _ = index.indices(len(self))
        rows = []
        offset = 0
        for queryset, n in self._counted_parts():
            if offset >= stop:
                break
            if start < offset + n:
                objects = [self.obj] if queryset is None else queryset[max(start - offset, 0) : stop - offset]
                rows.extend(map(self._row, objects))
            offset += n
        return rows

    @staticmethod
    def _row(x):
        return {
            "model": type(x).__name__,
            "id": x.id if hasattr(x, "id") else None,
            "name": str(x) if not isinstance(x, Token) else "<APITokenIsHidden>",
        }


class DeletePreviewModelMixin:
    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.DeletePreviewSerializer(many=True),
        },
    )
    @action(detail=True, methods=["get"], filter_backends=[], suffix="List")
    def delete_preview(self, request, pk=None):
        obj = self.get_object()
        # The preview lists what a delete would remove, so viewsets guarded by model
        # permissions require the delete permission here as well.
        for permission in self.get_permissions():
            if isinstance(permission, DjangoModelPermissions):
                if not request.user.has_perms(permission.get_required_permissions("DELETE", type(obj))):
                    self.permission_denied(request)

        # Cap the page whatever the configured paginator allows: each row is rendered in Python.
        paginator = self.paginator
        for attr in ("max_limit", "max_page_size"):
            if hasattr(paginator, attr):
                current = getattr(paginator, attr)
                setattr(paginator, attr, min(current or DELETE_PREVIEW_MAX_PAGE_SIZE, DELETE_PREVIEW_MAX_PAGE_SIZE))

        with Endpoint.allow_endpoint_init():  # TODO: Delete this after the move to Locations
            page = self.paginate_queryset(DeletePreviewRows(obj))
            serializer = serializers.DeletePreviewSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
