"""
Efficient cascade delete utility for Django models.

Uses compiled SQL (via SQLDeleteCompiler/SQLUpdateCompiler) to perform cascade
DELETE and SET_NULL operations by walking model._meta.related_objects recursively.
This bypasses Django's Collector and per-object signal overhead.

Based on: https://dev.to/redhap/efficient-django-delete-cascade-43i5
"""

import logging

from django.db import models, transaction
from django.db.models.sql.compiler import SQLDeleteCompiler

logger = logging.getLogger(__name__)


def get_delete_sql(query):
    """Compile a DELETE SQL statement from a QuerySet."""
    return SQLDeleteCompiler(
        query.query, transaction.get_connection(), query.db,
    ).as_sql()


def get_update_sql(query, **updatespec):
    """Compile an UPDATE SQL statement from a QuerySet with the given column values."""
    if not query.query.can_filter():
        msg = "Cannot filter this query"
        raise ValueError(msg)
    query.for_write = True
    q = query.query.chain(models.sql.UpdateQuery)
    q.add_update_values(updatespec)
    q._annotations = None
    return q.get_compiler(query.db).as_sql()


def execute_compiled_sql(sql, params=None):
    """Execute compiled SQL directly via connection.cursor()."""
    with transaction.get_connection().cursor() as cur:
        cur.execute(sql, params or None)
        return cur.rowcount


def execute_delete_sql(query):
    """Compile and execute a DELETE statement from a QuerySet."""
    return execute_compiled_sql(*get_delete_sql(query))


def execute_update_sql(query, **updatespec):
    """Compile and execute an UPDATE statement from a QuerySet."""
    return execute_compiled_sql(*get_update_sql(query, **updatespec))


def cascade_delete(from_model, instance_pk_query, skip_relations=None, base_model=None, level=0):
    """
    Recursively walk Django model relations and execute compiled SQL
    to perform cascade DELETE / SET_NULL without the Collector.

    Walks from_model._meta.related_objects to discover all FK relations,
    recurses into CASCADE children first (bottom-up), then deletes at the
    current level. No query execution until recursion unwinds.

    Includes any related object in Dojo-Pro

    Args:
        from_model: The model class to delete from.
        instance_pk_query: QuerySet selecting the records to delete.
        skip_relations: Set of model classes to skip (e.g. self-referential FKs).
        base_model: Root model class (set automatically on first call).
        level: Recursion depth (for logging only).

    Returns:
        Number of records deleted at this level.

    """
    if skip_relations is None:
        skip_relations = set()
    if base_model is None:
        base_model = from_model

    instance_pk_query = instance_pk_query.values_list("pk").order_by()

    logger.debug(
        "cascade_delete level %d for %s: checking relations of %s",
        level, base_model.__name__, from_model.__name__,
    )

    for relation in from_model._meta.related_objects:
        related_model = relation.related_model
        if related_model in skip_relations:
            logger.debug("cascade_delete: skipping %s", related_model.__name__)
            continue

        on_delete = relation.on_delete
        if on_delete is None:
            logger.debug(
                "cascade_delete: no on_delete for %s -> %s, skipping",
                from_model.__name__, related_model.__name__,
            )
            continue

        on_delete_name = on_delete.__name__
        fk_column = relation.remote_field.column
        filterspec = {f"{fk_column}__in": models.Subquery(instance_pk_query)}

        if on_delete_name == "SET_NULL":
            count = execute_update_sql(
                related_model.objects.filter(**filterspec),
                **{fk_column: None},
            )
            logger.debug(
                "cascade_delete: SET NULL on %d %s records",
                count, related_model.__name__,
            )

        elif on_delete_name == "CASCADE":
            related_pk_query = related_model.objects.filter(**filterspec).values_list(
                related_model._meta.pk.name,
            )
            # Recurse into children first (bottom-up deletion)
            cascade_delete(
                related_model, related_pk_query,
                skip_relations=skip_relations,
                base_model=base_model,
                level=level + 1,
            )

        elif on_delete_name == "DO_NOTHING":
            logger.debug(
                "cascade_delete: DO_NOTHING for %s, skipping",
                related_model.__name__,
            )

        else:
            logger.warning(
                "cascade_delete: unhandled on_delete=%s for %s -> %s, skipping",
                on_delete_name, from_model.__name__, related_model.__name__,
            )

    # After all children are deleted, delete records at this level
    if level == 0:
        del_query = instance_pk_query
    else:
        filterspec = {f"{from_model._meta.pk.name}__in": models.Subquery(instance_pk_query)}
        del_query = from_model.objects.filter(**filterspec)

    count = execute_delete_sql(del_query)
    logger.debug(
        "cascade_delete level %d: deleted %d %s records",
        level, count, from_model.__name__,
    )
    return count
