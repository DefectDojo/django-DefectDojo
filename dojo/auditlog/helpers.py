"""
Audit-log helpers: display formatting + Celery-context wrappers.

* Display helpers annotate pghistory event querysets with ``object_str``
  and ``object_url`` for templates.
* Celery-context helpers serialize/restore the active pghistory context
  across a task boundary so events dispatched from a worker share the
  ``pgh_context_id`` of the originating request.
"""
import logging
import uuid
from collections import defaultdict
from contextlib import nullcontext

from django.apps import apps
from pghistory import runtime as pghistory_runtime

logger = logging.getLogger(__name__)


# Populated by services.register_django_pghistory_models() — maps
# proxy_name -> (parent_model, field_name) for tag through-models.
TAG_MODEL_MAPPING = {}


def _reconstruct_object_str(model_name: str, pgh_data: dict, obj_id: int) -> str:
    """Reconstruct object string representation from pgh_data snapshot."""
    if not pgh_data:
        return f"{model_name} #{obj_id}" if obj_id else "N/A"

    model_lower = model_name.lower()

    if model_lower in {"finding", "finding_template"}:
        if pgh_data.get("title"):
            return str(pgh_data["title"])
    elif model_lower == "engagement":
        name = pgh_data.get("name", "")
        if name:
            return f"Engagement {obj_id}: {name}"
    elif model_lower == "dojo_user":
        first = pgh_data.get("first_name", "")
        last = pgh_data.get("last_name", "")
        if first or last:
            return f"{first} {last}".strip()
        if pgh_data.get("username"):
            return pgh_data["username"]
    elif model_lower in {"product", "product_type", "finding_group", "test_type"}:
        if pgh_data.get("name"):
            return str(pgh_data["name"])
    elif model_lower == "test":
        if pgh_data.get("title"):
            return pgh_data["title"]
    elif model_lower == "endpoint":
        if pgh_data.get("host"):
            return pgh_data["host"]

    for field in ["title", "name", "username", "label", "host"]:
        if pgh_data.get(field):
            return str(pgh_data[field])

    return f"{model_name} #{obj_id}" if obj_id else "N/A"


def process_events_for_display(events):
    """Process events to add object_str and object_url."""
    from dojo.models import Dojo_User  # noqa: PLC0415 -- avoid circular import

    ids_by_model = defaultdict(set)
    user_ids = set()
    tag_ids_by_model = defaultdict(set)

    for event in events:
        if not hasattr(event, "pgh_obj_model") or not event.pgh_obj_model:
            continue
        model_name = event.pgh_obj_model.split(".")[-1]
        pgh_data = getattr(event, "pgh_data", None) or {}
        obj_id = getattr(event, "pgh_obj_id", None)

        if model_name == "FindingReviewers":
            if user_id := pgh_data.get("dojo_user_id"):
                user_ids.add(int(user_id))
        elif model_name in TAG_MODEL_MAPPING:
            for key, value in pgh_data.items():
                if key.startswith("tagulous_") and key.endswith("_id") and value:
                    tag_ids_by_model[model_name].add(int(value))
                    break
        elif obj_id:
            ids_by_model[model_name].add(int(obj_id))

    instances_cache = {}
    for model_name, obj_ids in ids_by_model.items():
        if obj_ids:
            try:
                model_class = apps.get_model("dojo", model_name)
                instances_cache[model_name] = {
                    obj.id: obj for obj in model_class.objects.filter(id__in=obj_ids)
                }
            except LookupError:
                pass

    users_cache = {}
    if user_ids:
        users_cache = {u.id: u for u in Dojo_User.objects.filter(id__in=user_ids)}

    tags_cache = {}
    for model_name, tag_ids in tag_ids_by_model.items():
        if tag_ids and model_name in TAG_MODEL_MAPPING:
            parent_model, field_name = TAG_MODEL_MAPPING[model_name]
            tag_model = parent_model._meta.get_field(field_name).remote_field.model
            tags_cache[model_name] = {t.id: t.name for t in tag_model.objects.filter(id__in=tag_ids)}

    for event in events:
        try:
            if not hasattr(event, "pgh_obj_model") or not event.pgh_obj_model:
                event.object_str = "N/A"
                event.object_url = None
                continue

            model_name = event.pgh_obj_model.split(".")[-1]
            pgh_data = getattr(event, "pgh_data", None) or {}
            obj_id = getattr(event, "pgh_obj_id", None)
            obj_id_int = int(obj_id) if obj_id else None

            if model_name == "FindingReviewers":
                user_id = pgh_data.get("dojo_user_id")
                user = users_cache.get(int(user_id)) if user_id else None
                if user:
                    event.object_str = f"Reviewer: {user.get_full_name() or user.username}"
                else:
                    event.object_str = f"FindingReviewers #{obj_id}"
                event.object_url = None
            elif model_name in TAG_MODEL_MAPPING:
                tag_name = None
                for key, value in pgh_data.items():
                    if key.startswith("tagulous_") and key.endswith("_id") and value:
                        tag_name = tags_cache.get(model_name, {}).get(int(value))
                        break
                if tag_name:
                    event.object_str = f"Tag: {tag_name}"
                else:
                    event.object_str = f"{model_name} #{obj_id}"
                event.object_url = None
            else:
                instance = instances_cache.get(model_name, {}).get(obj_id_int)
                if instance:
                    event.object_str = str(instance)
                    event.object_url = instance.get_absolute_url() if hasattr(instance, "get_absolute_url") else None
                else:
                    event.object_str = _reconstruct_object_str(model_name, pgh_data, obj_id)
                    event.object_url = None
        except Exception:
            logger.debug("Error processing event: %s", event, exc_info=True)
            event.object_str = f"{getattr(event, 'pgh_obj_model', 'Unknown')} #{getattr(event, 'pgh_obj_id', '?')}"
            event.object_url = None

    return events


# ---------------------------------------------------------------------------
# Celery-context wrappers (formerly dojo/pghistory_utils.py)
#
# pghistory uses thread-local storage, so context is lost when tasks run in
# Celery workers. These helpers capture context in the sender process and
# recreate it in the worker, ensuring all events share the same
# pgh_context_id.
# ---------------------------------------------------------------------------


def get_serializable_pghistory_context():
    """
    Capture the current pghistory context for passing to Celery tasks.

    Returns a JSON-serializable dict with context id and metadata,
    or None if no context is active.
    """
    if hasattr(pghistory_runtime._tracker, "value"):
        ctx = pghistory_runtime._tracker.value
        return {
            "id": str(ctx.id),
            "metadata": ctx.metadata.copy(),
        }
    return None


class PgHistoryContextFromTask:

    """
    Context manager to apply pghistory context received from a Celery task.

    This recreates the exact same context (with the same UUID) that was
    active when the task was dispatched, ensuring all events share the
    same pgh_context_id.

    Usage:
        pgh_context = kwargs.pop("_pgh_context", None)
        with PgHistoryContextFromTask(pgh_context):
            # Task body runs here with context applied
    """

    def __init__(self, context_data):
        self.context_data = context_data
        self._pre_execute_hook = None
        self._owns_context = False

    def __enter__(self):
        if not self.context_data:
            return None

        from django.db import connection  # noqa: PLC0415

        context_id = uuid.UUID(self.context_data["id"])
        metadata = self.context_data["metadata"]

        if not hasattr(pghistory_runtime._tracker, "value"):
            self._pre_execute_hook = connection.execute_wrapper(
                pghistory_runtime._inject_history_context,
            )
            self._pre_execute_hook.__enter__()
            pghistory_runtime._tracker.value = pghistory_runtime.Context(
                id=context_id,
                metadata=metadata,
            )
            self._owns_context = True
        else:
            pghistory_runtime._tracker.value.metadata.update(metadata)

        return pghistory_runtime._tracker.value

    def __exit__(self, *exc):
        if self._owns_context and self._pre_execute_hook:
            delattr(pghistory_runtime._tracker, "value")
            self._pre_execute_hook.__exit__(*exc)


def get_pghistory_context_manager(context_data):
    """
    Return appropriate context manager for the given context data.

    Returns PgHistoryContextFromTask if context_data is provided,
    otherwise returns a no-op nullcontext.
    """
    if context_data:
        return PgHistoryContextFromTask(context_data)
    return nullcontext()
