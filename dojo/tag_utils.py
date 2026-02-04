from __future__ import annotations

from collections.abc import Iterable

from django.conf import settings
from django.db import models, transaction
from tagulous.utils import parse_tags

from dojo.models import Product  # local import to avoid circulars at import time


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


__all__ = ["bulk_add_tags_to_instances"]
