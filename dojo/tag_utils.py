from __future__ import annotations

import logging
from collections.abc import Iterable

from django.conf import settings
from django.db import models, transaction
from tagulous.utils import parse_tags

from dojo.models import Product  # local import to avoid circulars at import time

logger = logging.getLogger(__name__)


def bulk_add_tags_to_instances(tag_or_tags, instances, tag_field_name: str = "tags", batch_size: int | None = None) -> int:
    """
    Efficiently add tag(s) to many model instances.

    - tags can be a single string, an iterable of strings or tag objects, or a Tagulous edit string
    - Works with QuerySet or list of instances
    - Does not (yet) enforce TagField max_count
    - Will clear the prefetch cache for the tag_field_name field to avoid stale results

    Returns the number of new relationships created across all provided tags.
    """
    # Resolve batch size from settings if not provided
    if batch_size is None:
        batch_size = getattr(settings, "TAG_BULK_ADD_BATCH_SIZE", 1000)

    # Convert QuerySet to list if needed
    if hasattr(instances, "model"):
        instances = list(instances)

    if not instances:
        return 0

    # Get model class and resolve TagField from first instance
    model_class = instances[0].__class__

    # Explicitly reject Product instances for now. Bulk tagging Products should
    # trigger tag inheritance propagation to child objects, which is normally
    # handled by m2m signals that this utility bypasses. To avoid partial
    # updates or surprising side effects, we disallow Products here. Use the
    # standard `.tags.add(...)` API or a dedicated propagation-aware helper.
    if model_class is Product:
        msg = "bulk_add_tags_to_instances: Product instances are not supported; use Product.tags.add() or a propagation-aware helper"
        raise ValueError(msg)

    try:
        tag_field = model_class._meta.get_field(tag_field_name)
    except Exception:
        msg = f"Model {model_class.__name__} does not have field '{tag_field_name}'"
        raise ValueError(msg)

    if not hasattr(tag_field, "tag_options"):
        msg = f"Field '{tag_field_name}' is not a TagField"
        raise ValueError(msg)

    tag_model = tag_field.related_model
    through_model = tag_field.remote_field.through

    # Normalize tags into a list of tag names
    tag_names = []
    try:
        if isinstance(tag_or_tags, str):
            space_delimiter = getattr(tag_field, "tag_options", None).space_delimiter if hasattr(tag_field, "tag_options") else False
            tag_names = parse_tags(tag_or_tags, space_delimiter=space_delimiter)
        elif isinstance(tag_or_tags, Iterable):
            tag_names = [getattr(t, "name", str(t)) for t in tag_or_tags]
        else:
            tag_names = [str(tag_or_tags)]
    except Exception:
        tag_names = [str(tag_or_tags)]

    total_created = 0

    # Resolve through model field names once
    through_fields = {f.name: f for f in through_model._meta.fields}
    source_field_name = None
    target_field_name = None
    for field_name, field in through_fields.items():
        if hasattr(field, "remote_field") and field.remote_field:
            if field.remote_field.model == model_class:
                source_field_name = field_name
            elif field.remote_field.model == tag_model:
                target_field_name = field_name

    for single_tag_name in tag_names:
        if not single_tag_name:
            continue

        # Query 1: ensure the tag exists once per tag
        if tag_field.tag_options.case_sensitive:
            tag, _ = tag_model.objects.get_or_create(
                name=single_tag_name,
                defaults={"name": single_tag_name, "protected": False},
            )
        else:
            tag, _ = tag_model.objects.get_or_create(
                name__iexact=single_tag_name,
                defaults={"name": single_tag_name, "protected": False},
            )

        # Process in batches to manage memory
        for i in range(0, len(instances), batch_size):
            batch_instances = instances[i:i + batch_size]

            with transaction.atomic():
                # Query 2: Find existing relationships in this batch
                batch_ids = [instance.pk for instance in batch_instances]
                existing_ids = set(
                    through_model.objects.filter(
                        **{target_field_name: tag.pk},
                    ).filter(
                        **{f"{source_field_name}__in": batch_ids},
                    ).values_list(source_field_name, flat=True),
                )

                # Find new instances that don't have this tag yet
                new_instances = [instance for instance in batch_instances if instance.pk not in existing_ids]

                if new_instances:
                    # Query 3: Bulk create new relationships
                    relationships = []
                    for instance in new_instances:
                        relationship_data = {
                            source_field_name: instance,
                            target_field_name: tag,
                        }
                        relationships.append(through_model(**relationship_data))

                    # Use ignore_conflicts=True to handle race conditions
                    actually_created = through_model.objects.bulk_create(
                        relationships,
                        ignore_conflicts=True,
                    )

                    # Count how many were actually created (Django 4.0+)
                    batch_created = (
                        len(actually_created)
                        if hasattr(actually_created, "__len__")
                        else len(new_instances)
                    )

                    total_created += batch_created

                    # Query 4: Update tag count
                    tag_model.objects.filter(pk=tag.pk).update(
                        count=models.F("count") + batch_created,
                    )

                    # Invalidate Django's prefetch cache for the tag relation on
                    # the affected instances so subsequent access reloads from DB.
                    # This avoids stale results when callers reuse the same
                    # in-memory objects after the bulk operation.
                    # It will result in a refresh from DB if the caller calls instance.tags
                    # In theory we could update the django-tagulous private cache of tags
                    # but that would create a bit of a tight link with tagulous internals.
                    for instance in new_instances:
                        prefetch_cache = getattr(instance, "_prefetched_objects_cache", None)
                        if prefetch_cache is not None:
                            prefetch_cache.pop(tag_field_name, None)

    return total_created


def bulk_add_tag_mapping(
    tag_to_instances: dict[str, list],
    tag_field_name: str = "tags",
    batch_size: int | None = None,
) -> int:
    """
    Add different tags to different sets of instances in ~5 queries regardless of tag count.

    Unlike calling ``bulk_add_tags_to_instances`` once per unique tag — which issues
    O(unique_tags) queries — this function batches all work:

    1. Fetch all existing tag objects in one query.
    2. Bulk-create any missing tag objects (one INSERT + one re-fetch if needed).
    3. Fetch all pre-existing through-model rows for these (instance, tag) pairs in one query.
    4. Bulk-create all new relationships in one query (batched by ``batch_size``).
    5. Update all tag counts in one ``UPDATE … CASE WHEN …`` query.

    Args:
        tag_to_instances: mapping of tag_name -> list of instances that should receive
            that tag.  All instances must be of the same model type.
        tag_field_name: name of the TagField on the model (default: ``"tags"``).
        batch_size: ``bulk_create`` batch size; defaults to ``TAG_BULK_ADD_BATCH_SIZE``
            setting (1000).

    Returns:
        Total number of new tag relationships created.

    """
    from collections import defaultdict  # noqa: PLC0415

    from django.db.models import Case, IntegerField, When  # noqa: PLC0415
    from django.db.models.functions import Lower  # noqa: PLC0415

    if not tag_to_instances:
        return 0

    if batch_size is None:
        batch_size = getattr(settings, "TAG_BULK_ADD_BATCH_SIZE", 1000)

    all_instances = [inst for insts in tag_to_instances.values() for inst in insts]
    if not all_instances:
        return 0

    model_class = all_instances[0].__class__

    if model_class is Product:
        msg = "bulk_add_tag_mapping: Product instances are not supported; use Product.tags.add() or a propagation-aware helper"
        raise ValueError(msg)

    try:
        tag_field = model_class._meta.get_field(tag_field_name)
    except Exception:
        msg = f"Model {model_class.__name__} does not have field '{tag_field_name}'"
        raise ValueError(msg)

    if not hasattr(tag_field, "tag_options"):
        msg = f"Field '{tag_field_name}' is not a TagField"
        raise ValueError(msg)

    tag_model = tag_field.related_model
    through_model = tag_field.remote_field.through
    case_sensitive = tag_field.tag_options.case_sensitive

    source_field_name = None
    target_field_name = None
    for field in through_model._meta.fields:
        if hasattr(field, "remote_field") and field.remote_field:
            if field.remote_field.model == model_class:
                source_field_name = field.name
            elif field.remote_field.model == tag_model:
                target_field_name = field.name

    all_tag_names = list(tag_to_instances.keys())

    # --- Query 1: fetch existing tag objects ---
    if case_sensitive:
        existing_tags: dict[str, object] = {
            t.name: t
            for t in tag_model.objects.filter(name__in=all_tag_names)
        }
        missing_names = [n for n in all_tag_names if n not in existing_tags]
    else:
        # Annotate with lowercased name for a case-insensitive IN lookup
        existing_tags = {
            t.name_lower: t
            for t in tag_model.objects.annotate(name_lower=Lower("name")).filter(
                name_lower__in=[n.lower() for n in all_tag_names],
            )
        }
        missing_names = [n for n in all_tag_names if n.lower() not in existing_tags]

    # --- Query 2: create missing tag objects then re-fetch to get their PKs ---
    if missing_names:
        tag_model.objects.bulk_create(
            [tag_model(name=n, protected=False) for n in missing_names],
            ignore_conflicts=True,
        )
        if case_sensitive:
            existing_tags.update(
                {t.name: t for t in tag_model.objects.filter(name__in=missing_names)},
            )
        else:
            existing_tags.update(
                {
                    t.name_lower: t
                    for t in tag_model.objects.annotate(name_lower=Lower("name")).filter(
                        name_lower__in=[n.lower() for n in missing_names],
                    )
                },
            )

    def _key(name: str) -> str:
        return name if case_sensitive else name.lower()

    # --- Query 3: fetch all pre-existing (instance, tag) through-model rows ---
    all_instance_ids = {inst.pk for inst in all_instances}
    all_tag_pks = {tag.pk for tag in existing_tags.values()}

    existing_pairs: set[tuple] = set(
        through_model.objects.filter(
            **{f"{source_field_name}__in": all_instance_ids},
            **{f"{target_field_name}__in": all_tag_pks},
        ).values_list(source_field_name, target_field_name),
    )

    new_relationships = []
    created_per_tag: dict[int, int] = defaultdict(int)

    for tag_name, instances in tag_to_instances.items():
        tag = existing_tags.get(_key(tag_name))
        if tag is None:
            continue
        for instance in instances:
            if (instance.pk, tag.pk) not in existing_pairs:
                new_relationships.append(
                    through_model(**{source_field_name: instance, target_field_name: tag}),
                )
                created_per_tag[tag.pk] += 1

    if not new_relationships:
        return 0

    # --- Query 4: bulk-create all new relationships (batched for memory) ---
    total_created = 0
    with transaction.atomic():
        for i in range(0, len(new_relationships), batch_size):
            batch = new_relationships[i : i + batch_size]
            actually_created = through_model.objects.bulk_create(batch, ignore_conflicts=True)
            total_created += (
                len(actually_created) if hasattr(actually_created, "__len__") else len(batch)
            )

    # --- Query 5: update all tag counts in one UPDATE … CASE WHEN … ---
    tag_model.objects.filter(pk__in=list(created_per_tag.keys())).update(
        count=Case(
            *[
                When(pk=pk, then=models.F("count") + delta)
                for pk, delta in created_per_tag.items()
            ],
            output_field=IntegerField(),
        ),
    )

    for instance in all_instances:
        prefetch_cache = getattr(instance, "_prefetched_objects_cache", None)
        if prefetch_cache is not None:
            prefetch_cache.pop(tag_field_name, None)

    return total_created


def bulk_apply_parser_tags(findings_with_tags: list) -> None:
    """
    Bulk-apply per-finding parser tags collected during an import loop.

    Delegates to ``bulk_add_tag_mapping`` to process all tags in ~5 queries total,
    regardless of how many unique tag values the parser produced.

    Args:
        findings_with_tags: list of ``(finding, [tag_str, ...])`` pairs accumulated
            during the import loop (only for findings whose parser supplied tags).

    """
    from collections import defaultdict  # noqa: PLC0415

    tag_to_findings: dict = defaultdict(list)
    for finding, tag_list in findings_with_tags:
        for tag in tag_list:
            if tag:
                tag_to_findings[tag].append(finding)

    bulk_add_tag_mapping(tag_to_findings)


def bulk_remove_all_tags(model_class, instance_ids_qs):
    """
    Remove all tags from instances identified by the given ID subquery.

    Auto-discovers all TagFields on the model, decrements tag counts correctly,
    and deletes through-table rows.
    Accepts a QuerySet of IDs (as a subquery) to avoid materializing large ID lists.

    Args:
        model_class: The model class (e.g. Finding, Product).
        instance_ids_qs: A QuerySet producing instance PKs (used as subquery).

    """
    tag_fields = [
        field for field in model_class._meta.get_fields()
        if hasattr(field, "tag_options")
    ]

    for tag_field in tag_fields:

        tag_model = tag_field.related_model
        through_model = tag_field.remote_field.through

        # Find the FK column that points to the source model
        source_field_name = None
        target_field_name = None
        for field in through_model._meta.get_fields():
            if hasattr(field, "remote_field") and field.remote_field:
                if field.remote_field.model == model_class:
                    source_field_name = field.name
                elif field.remote_field.model == tag_model:
                    target_field_name = field.name

        if not source_field_name or not target_field_name:
            continue

        # Get affected tag IDs and their counts before deletion
        affected_tags = (
            through_model.objects.filter(**{f"{source_field_name}__in": instance_ids_qs})
            .values(target_field_name)
            .annotate(num=models.Count("id"))
        )

        # Decrement tag counts. Tag counts are not used in DefectDojo but we
        # maintain them to avoid breaking tagulous's internal bookkeeping.
        for entry in affected_tags:
            tag_model.objects.filter(pk=entry[target_field_name]).update(
                count=models.F("count") - entry["num"],
            )

        # Delete through-table rows
        count, _ = through_model.objects.filter(
            **{f"{source_field_name}__in": instance_ids_qs},
        ).delete()

        if count:
            logger.debug(
                "bulk_remove_all_tags: removed %d %s.%s through-table rows",
                count, model_class.__name__, tag_field.name,
            )


__all__ = ["bulk_add_tag_mapping", "bulk_add_tags_to_instances", "bulk_apply_parser_tags", "bulk_remove_all_tags"]
