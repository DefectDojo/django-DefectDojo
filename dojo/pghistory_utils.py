"""
Utilities for passing pghistory context to Celery tasks.

pghistory uses thread-local storage, so context is lost when tasks run
in Celery workers. These utilities allow capturing context in the sender
process and recreating it in the worker.
"""
import uuid
from contextlib import nullcontext

from pghistory import runtime as pghistory_runtime


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
        """
        Initialize with context data from Celery kwargs.

        Args:
            context_data: Dict with "id" (UUID string) and "metadata" (dict),
                         or None for no-op behavior.

        """
        self.context_data = context_data
        self._pre_execute_hook = None
        self._owns_context = False

    def __enter__(self):
        if not self.context_data:
            return None

        from django.db import connection  # noqa: PLC0415

        context_id = uuid.UUID(self.context_data["id"])
        metadata = self.context_data["metadata"]

        # Only create a new context if one doesn't already exist
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
            # Context already exists, just merge metadata
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
