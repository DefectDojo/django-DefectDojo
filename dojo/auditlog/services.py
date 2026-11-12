"""
Audit-log services: pghistory model registration, retention/cleanup, and
startup configuration.

django-auditlog support has been removed; only django-pghistory is used.
"""
import logging
import os
import sys

import pghistory
from dateutil.relativedelta import relativedelta
from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.db import models
from django.utils import timezone

from dojo.auditlog.helpers import TAG_MODEL_MAPPING

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Indexes for reading an object's history
# ---------------------------------------------------------------------------


def history_lookup_index(name, field_name, *, nullable=False):
    """
    Index an event table's copy of a foreign key, so an object's history can be read through it.

    ``Events.objects.references(obj)`` reads every event table with a foreign key to ``obj``'s model,
    filtering each on ``<fk column> = <obj id>``. The copies carry no index of their own
    (``PGHISTORY_FOREIGN_KEY_FIELD`` sets ``db_index=False``, which keeps event writes cheap), so
    without this each history read scans its whole event table, a cost that grows with every event
    the instance has ever recorded rather than with the object's own. A nullable column is indexed
    only where it is set: the lookup never asks for NULL, and most rows of a column like
    ``duplicate_finding`` are NULL.
    """
    condition = models.Q(**{f"{field_name}__isnull": False}) if nullable else None
    return models.Index(fields=[field_name], name=name, condition=condition)


def _event_indexes(*lookup_indexes, previous_event=True):
    """
    The indexes a tracked model's event table carries, plus ``lookup_indexes``.

    ``previous_event`` adds ``(pgh_obj, pgh_id)``. pghistory computes each event's diff from the
    object's previous event (``pgh_obj_id = <obj> AND pgh_id < <event> ORDER BY pgh_id DESC LIMIT
    1``). With only ``pgh_obj_id`` indexed, Postgres reads every event of the object to find that
    one row, for every event on a page: a page of 250 events of a finding with 20,000 took 60 s.
    A many-to-many through table leaves it out: each of its rows has an insert and maybe a delete.
    """
    indexes = [
        models.Index(fields=["pgh_created_at"]),
        models.Index(fields=["pgh_label"]),
        models.Index(fields=["pgh_context_id"]),
    ]
    if previous_event:
        indexes.append(models.Index(fields=["pgh_obj", "pgh_id"]))
    return [*indexes, *lookup_indexes]


# ---------------------------------------------------------------------------
# Retention / cleanup
# ---------------------------------------------------------------------------


def _flush_models_in_batches(models_to_flush, timestamp_field: str, retention_period: int, batch_size: int, max_batches: int, *, dry_run: bool = False) -> tuple[int, int, bool]:
    """
    Generic batched deletion by timestamp for a set of models.

    Returns (deleted_or_would_delete_total, batches_done_or_needed, reached_limit)
    """
    # Use a timestamp and not a date. this allows for efficient databse index use.
    cutoff_dt = timezone.now() - relativedelta(months=retention_period)
    logger.info("Audit flush cutoff datetime: %s (retention_period=%s months)", cutoff_dt, retention_period)

    total_deleted = 0
    total_batches = 0
    reached_any_limit = False

    for Model in models_to_flush:
        deleted_total = 0
        batches_done = 0
        filter_kwargs = {f"{timestamp_field}__lt": cutoff_dt}
        last_pk = None
        verb = "Would delete" if dry_run else "Deleted"

        while batches_done < max_batches:
            batch_qs = Model.objects.filter(**filter_kwargs)
            if last_pk is not None:
                batch_qs = batch_qs.filter(pk__gt=last_pk)
            batch_qs = batch_qs.order_by("pk")

            pks = list(batch_qs.values_list("pk", flat=True)[:batch_size])
            if not pks:
                if batches_done == 0:
                    logger.info("No outdated %s entries found", Model._meta.object_name)
                break

            if dry_run:
                deleted_count = len(pks)
            else:
                qs = Model.objects.filter(pk__in=pks)
                deleted_count = int(qs._raw_delete(qs.db))

            deleted_total += deleted_count
            batches_done += 1
            last_pk = pks[-1]

            logger.info(
                "%s %s batch %s (size ~%s), total %s: %s",
                verb,
                Model._meta.object_name,
                batches_done,
                batch_size,
                verb.lower(),
                deleted_total,
            )

        total_deleted += deleted_total
        total_batches += batches_done
        if batches_done >= max_batches:
            reached_any_limit = True

    return total_deleted, total_batches, reached_any_limit


def _iter_pghistory_event_models():
    """Yield pghistory Event models registered under the dojo app."""
    for model in apps.get_app_config("dojo").get_models():
        if model._meta.object_name.endswith("Event") and any(f.name == "pgh_created_at" for f in model._meta.fields):
            yield model


def _flush_pghistory_events(retention_period: int, batch_size: int, max_batches: int, *, dry_run: bool = False) -> tuple[int, int, bool]:
    models_to_flush = list(_iter_pghistory_event_models())
    return _flush_models_in_batches(models_to_flush, "pgh_created_at", retention_period, batch_size, max_batches, dry_run=dry_run)


def run_flush_auditlog(retention_period: int | None = None,
                       batch_size: int | None = None,
                       max_batches: int | None = None,
                       *,
                       dry_run: bool = False) -> tuple[int, int, bool]:
    """
    Deletes audit entries older than the configured retention from django-pghistory log entries.

    Returns a tuple of (deleted_total, batches_done, reached_limit).
    """
    retention_period = retention_period if retention_period is not None else getattr(settings, "AUDITLOG_FLUSH_RETENTION_PERIOD", -1)
    if retention_period < 0:
        logger.info("Flushing audit logs is disabled")
        return 0, 0, False

    batch_size = batch_size if batch_size is not None else getattr(settings, "AUDITLOG_FLUSH_BATCH_SIZE", 1000)
    max_batches = max_batches if max_batches is not None else getattr(settings, "AUDITLOG_FLUSH_MAX_BATCHES", 100)

    phase = "DRY RUN" if dry_run else "Cleanup"
    logger.info("Running %s for django-pghistory entries with %d Months retention across all backends", phase, retention_period)
    p_deleted, p_batches, p_limit = _flush_pghistory_events(retention_period, batch_size, max_batches, dry_run=dry_run)

    verb = "would delete" if dry_run else "deleted"
    logger.info("Audit flush summary: pghistory %s=%s batches=%s", verb, p_deleted, p_batches)

    return p_deleted, p_batches, bool(p_limit)


# ---------------------------------------------------------------------------
# pghistory model registration
# ---------------------------------------------------------------------------


def register_django_pghistory_models():
    """
    Register models with django-pghistory (always called to avoid migrations).

    Note: This function is always called regardless of audit logging settings because:
    1. Django migrations are generated based on model registration at import time
    2. If pghistory models are not registered, Django will try to create migrations
       to remove the pghistory tables when the models are not found
    3. This would cause migration conflicts and database inconsistencies
    4. By always registering the models, we ensure the database schema remains
       stable while controlling audit behavior through trigger enable/disable
    So we always register the models and make migrations for them.
    Then we control the enabling/disabling by enabling/disabling the underlying database
    triggers.
    """
    # Import models inside function to avoid AppRegistryNotReady errors
    from dojo.location.models import Location  # noqa: PLC0415
    from dojo.models import (  # noqa: PLC0415
        App_Analysis,
        Dojo_User,
        # TODO: Delete this after the move to Locations
        Endpoint,
        Engagement,
        Finding,
        Finding_Group,
        Finding_Template,
        Notification_Webhooks,
        Objects_Product,
        Product,
        Product_Type,
        Risk_Acceptance,
        Test,
    )
    from dojo.url.models import URL  # noqa: PLC0415

    if "shell" not in sys.argv:
        logger.info("Registering models with django-pghistory")

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        exclude=["password"],
        meta={
            "indexes": _event_indexes(),
        },
    )(Dojo_User)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(
                history_lookup_index("dojo_endpointevt_product_hist", "product", nullable=True),
            ),
        },
    )(Endpoint)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(
                history_lookup_index("dojo_engagementevt_prod_hist", "product"),
            ),
        },
    )(Engagement)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(
                history_lookup_index("dojo_findingevt_test_hist", "test"),
                history_lookup_index("dojo_findingevt_dupe_hist", "duplicate_finding", nullable=True),
            ),
        },
    )(Finding)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(
                history_lookup_index("dojo_findinggroupevt_test_hist", "test"),
            ),
        },
    )(Finding_Group)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(),
        },
    )(Product_Type)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(
                history_lookup_index("dojo_productevt_prodtype_hist", "prod_type"),
            ),
        },
    )(Product)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(
                history_lookup_index("dojo_testevt_engagement_hist", "engagement"),
                history_lookup_index("dojo_testevt_testtype_hist", "test_type"),
            ),
        },
    )(Test)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(),
        },
    )(Risk_Acceptance)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(),
        },
    )(Finding_Template)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        exclude=["header_name", "header_value"],
        meta={
            "indexes": _event_indexes(),
        },
    )(Notification_Webhooks)

    # Track Finding.reviewers ManyToMany relationship via a proxy on the
    # auto-generated through model. Defined inside the function because
    # Finding.reviewers.through requires Django's app registry to be ready.
    reviewers_through = Finding._meta.get_field("reviewers").remote_field.through

    class FindingReviewers(reviewers_through):
        class Meta:
            proxy = True

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "db_table": "dojo_finding_reviewersevent",
            "indexes": _event_indexes(
                history_lookup_index("dojo_findingrevevt_find_hist", "finding"), previous_event=False,
            ),
        },
    )(FindingReviewers)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(),
        },
    )(Location)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_backfill"),
        meta={
            "indexes": _event_indexes(
                history_lookup_index("dojo_urlevt_location_hist", "location"),
            ),
        },
    )(URL)

    # Track tag through models for all TagField relationships. Must use the
    # proxy pattern (like FindingReviewers) because tagulous auto-generates
    # the through models, which can't be imported at module level.
    tag_through_models = [
        # (Parent model, field name, proxy class name)
        (Finding, "tags", "FindingTags"),
        (Finding, "inherited_tags", "FindingInheritedTags"),
        (Product, "tags", "ProductTags"),
        (Engagement, "tags", "EngagementTags"),
        (Engagement, "inherited_tags", "EngagementInheritedTags"),
        (Test, "tags", "TestTags"),
        (Test, "inherited_tags", "TestInheritedTags"),
        (Endpoint, "tags", "EndpointTags"),
        (Endpoint, "inherited_tags", "EndpointInheritedTags"),
        (Finding_Template, "tags", "FindingTemplateTags"),
        (App_Analysis, "tags", "AppAnalysisTags"),
        (Objects_Product, "tags", "ObjectsProductTags"),
    ]

    # Models whose own changes are not tracked, so nothing reads a history of them and their tag
    # tables need no lookup index (an index there would only tax every tag write).
    untracked_tag_parents = {App_Analysis, Objects_Product}
    for parent_model, field_name, proxy_name in tag_through_models:
        TAG_MODEL_MAPPING[proxy_name] = (parent_model, field_name)

        through_model = parent_model._meta.get_field(field_name).remote_field.through

        proxy_class = type(proxy_name, (through_model,), {
            "__module__": __name__,
            "Meta": type("Meta", (), {"proxy": True}),
        })

        db_table = through_model._meta.db_table + "event"
        lookup_indexes = []
        if parent_model not in untracked_tag_parents:
            # The tagged object's history reads its tag events by the through row's key to it.
            # Index names stop at 30 characters: dojo_engagementinhtags_hist is the longest.
            tagged_field = next(f.name for f in through_model._meta.fields if f.related_model is parent_model)
            lookup_index_name = f"dojo_{proxy_name.lower().replace('inherited', 'inh')}_hist"
            lookup_indexes.append(history_lookup_index(lookup_index_name, tagged_field))

        pghistory.track(
            pghistory.InsertEvent(),
            pghistory.DeleteEvent(),
            pghistory.ManualEvent(label="initial_backfill"),
            meta={
                "db_table": db_table,
                "indexes": _event_indexes(*lookup_indexes, previous_event=False),
            },
        )(proxy_class)

    if "shell" not in sys.argv:
        logger.info("Successfully registered models with django-pghistory")


# ---------------------------------------------------------------------------
# Trigger / startup configuration
# ---------------------------------------------------------------------------


def configure_pghistory_triggers():
    """
    Configure pghistory triggers based on audit settings.

    This function should be called after Django startup and migrations to properly
    enable/disable pghistory triggers without database access warnings.
    """
    if not settings.ENABLE_AUDITLOG:
        logger.info("Audit logging disabled - disabling pghistory triggers")
        try:
            call_command("pgtrigger", "disable")
            logger.info("Successfully disabled pghistory triggers")
        except Exception as e:
            logger.error(f"Failed to disable pghistory triggers: {e}")
            raise
    else:
        try:
            call_command("pgtrigger", "enable")
            logger.info("Successfully enabled pghistory triggers")
        except Exception as e:
            logger.error(f"Failed to enable pghistory triggers: {e}")
            raise


def configure_audit_system():
    """
    Configure the audit system based on settings.

    django-auditlog is no longer supported. Only django-pghistory is allowed.
    """
    log_enabled = "shell" not in sys.argv

    auditlog_type_env = os.environ.get("DD_AUDITLOG_TYPE")
    if auditlog_type_env:
        error_msg = (
            "DD_AUDITLOG_TYPE environment variable is no longer supported. "
            "DefectDojo now exclusively uses django-pghistory for audit logging. "
            "Please remove DD_AUDITLOG_TYPE from your environment configuration. "
            "All new audit entries will be created using django-pghistory automatically."
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    if hasattr(settings, "AUDITLOG_TYPE"):
        error_msg = (
            "AUDITLOG_TYPE setting is no longer supported. "
            "DefectDojo now exclusively uses django-pghistory for audit logging. "
            "Please remove AUDITLOG_TYPE from your settings file (settings.dist.py or local_settings.py). "
            "All new audit entries will be created using django-pghistory automatically."
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    if not settings.ENABLE_AUDITLOG:
        if log_enabled:
            logger.info("Audit logging disabled")
        return

    if log_enabled:
        logger.info("Audit logging configured: django-pghistory")
