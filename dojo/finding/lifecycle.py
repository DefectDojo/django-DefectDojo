"""
Finding lifecycle provenance.

Records SEMANTIC events on findings — created by import X, closed because it
was gone from a re-upload, marked duplicate of Y, pushed to JIRA as KEY —
the "why", which neither field-level history (pghistory triggers) nor the
per-import action records (Test_Import_Finding_Action) can express.

Write discipline (this table must never become a performance problem):
- Transition-only: no rows for "matched, nothing changed" reimports.
- Batched: importers collect events and bulk_create them per finding batch.
- No signals, no per-row saves; detail values are truncated.
- The FK carries no database constraint and on_delete=DO_NOTHING, so bulk
  finding deletion never walks this table; orphans are swept by retention.
"""
import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from dojo.celery import app
from dojo.models import Finding_Lifecycle_Event

logger = logging.getLogger(__name__)

_DETAIL_MAX_CHARS = 256
_PURGE_BATCH_SIZE = 10000


def lifecycle_events_enabled() -> bool:
    return getattr(settings, "FINDING_LIFECYCLE_EVENTS_ENABLED", True)


def _truncate(value):
    if isinstance(value, str) and len(value) > _DETAIL_MAX_CHARS:
        return value[: _DETAIL_MAX_CHARS - 1] + "…"
    return value


def lifecycle_event(finding_id, action, detail=None, actor_type=Finding_Lifecycle_Event.ActorType.IMPORT):
    """Build an unsaved event; persist via record_lifecycle_events."""
    detail = {k: _truncate(v) for k, v in (detail or {}).items() if v is not None}
    return Finding_Lifecycle_Event(
        finding_id=finding_id,
        actor_type=actor_type,
        action=action,
        detail=detail,
    )


def record_lifecycle_events(events) -> None:
    """Bulk-persist events. Cheap no-op when disabled or empty."""
    if not events or not lifecycle_events_enabled():
        return
    Finding_Lifecycle_Event.objects.bulk_create(events, batch_size=1000)


def record_lifecycle_event(finding_id, action, detail=None, actor_type=Finding_Lifecycle_Event.ActorType.IMPORT) -> None:
    if not lifecycle_events_enabled():
        return
    record_lifecycle_events([lifecycle_event(finding_id, action, detail, actor_type)])


@app.task
def purge_finding_lifecycle_events(*args, **kwargs):
    """
    Delete lifecycle events older than the retention window, in batches.
    Also sweeps events orphaned by finding deletion (the FK intentionally
    carries no constraint so deletes never pay for this table).
    """
    retention_days = getattr(settings, "FINDING_LIFECYCLE_EVENTS_RETENTION_DAYS", 540)
    cutoff = timezone.now() - timedelta(days=retention_days)
    total = 0
    while True:
        batch_ids = list(
            Finding_Lifecycle_Event.objects.filter(created__lt=cutoff)
            .values_list("id", flat=True)[:_PURGE_BATCH_SIZE],
        )
        if not batch_ids:
            break
        deleted, _ = Finding_Lifecycle_Event.objects.filter(id__in=batch_ids).delete()
        total += deleted
    if total:
        logger.info("purged %d finding lifecycle events older than %d days", total, retention_days)
    return total
