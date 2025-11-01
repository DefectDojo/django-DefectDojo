"""
Audit logging configuration for DefectDojo.

This module handles registration of models with django-pghistory.
django-auditlog support has been removed.
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

logger = logging.getLogger(__name__)

# FindingReviewers proxy model will be created lazily in register_django_pghistory_models()
# Cannot be defined at module level because Finding.reviewers.through requires
# Django's app registry to be ready (AppRegistryNotReady error)
# The function is called from DojoAppConfig.ready() which guarantees the registry is ready


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
        if model._meta.object_name.endswith("Event"):
            # Ensure the model has pgh_created_at field
            if any(f.name == "pgh_created_at" for f in model._meta.fields):
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
    from dojo.models import (  # noqa: PLC0415
        Cred_User,
        Dojo_User,
        Endpoint,
        Engagement,
        Finding,
        Finding_Group,
        Finding_Template,
        Notification_Webhooks,
        Product,
        Product_Type,
        Risk_Acceptance,
        Test,
    )

    # Only log during actual application startup, not during shell commands
    if "shell" not in sys.argv:
        logger.info("Registering models with django-pghistory")

    # Register models with pghistory for tracking changes
    # Using pghistory.track() as a decorator function (correct syntax)
    # The function returns a decorator that should be applied to the model class

    # Track Dojo_User with excluded fields
    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        exclude=["password"],
        # add some indexes manually so we don't have to define a customer phistory Event model with overridden fields.
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Dojo_User)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Endpoint)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Engagement)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Finding)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Finding_Group)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Product_Type)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Product)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Test)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Risk_Acceptance)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Finding_Template)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        exclude=["password"],
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Cred_User)

    pghistory.track(
        pghistory.InsertEvent(),
        pghistory.UpdateEvent(condition=pghistory.AnyChange(exclude_auto=True)),
        pghistory.DeleteEvent(),
        pghistory.ManualEvent(label="initial_import"),
        exclude=["header_name", "header_value"],
        meta={
            "indexes": [
                models.Index(fields=["pgh_created_at"]),
                models.Index(fields=["pgh_label"]),
                models.Index(fields=["pgh_context_id"]),
            ],
        },
    )(Notification_Webhooks)

    # Track Finding.reviewers ManyToMany relationship
    # Create a proxy model for the through table as per pghistory docs:
    # https://django-pghistory.readthedocs.io/en/2.4.2/tutorial.html#tracking-many-to-many-events
    # Note: For auto-generated through models, we don't specify obj_fk/obj_field
    # as Django doesn't allow foreign keys to auto-generated through models
    #
    # We must create the proxy model here (not at module level) because:
    # 1. Finding.reviewers.through requires Django's app registry to be ready
    # 2. This function is called from DojoAppConfig.ready() which guarantees registry is ready
    # 3. We check if it already exists to avoid re-registration warnings
    #
    # Note: This pattern is not explicitly documented in Django's official documentation.
    # Django docs mention AppRegistryNotReady and AppConfig.ready() in general terms, but
    # don't specifically cover proxy models for auto-generated ManyToMany through tables.
    # This is a common pattern used by libraries like django-pghistory and is necessary
    # because accessing Model.field.through at module import time triggers AppRegistryNotReady.
    try:
        FindingReviewers = apps.get_model("dojo", "FindingReviewers")
    except LookupError:
        # Model doesn't exist yet, create it
        # Note: Finding is imported above, and apps registry is ready when this runs
        reviewers_through = Finding._meta.get_field("reviewers").remote_field.through

        class FindingReviewers(reviewers_through):
            class Meta:
                proxy = True

        pghistory.track(
            pghistory.InsertEvent(),
            pghistory.DeleteEvent(),
            pghistory.ManualEvent(label="initial_import"),
            meta={
                "db_table": "dojo_finding_reviewersevent",
                "indexes": [
                    models.Index(fields=["pgh_created_at"]),
                    models.Index(fields=["pgh_label"]),
                    models.Index(fields=["pgh_context_id"]),
                ],
            },
        )(FindingReviewers)

    # Only log during actual application startup, not during shell commands
    if "shell" not in sys.argv:
        logger.info("Successfully registered models with django-pghistory")


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
        # Only pghistory is supported now
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
    # Only log during actual application startup, not during shell commands
    log_enabled = "shell" not in sys.argv

    # Fail if DD_AUDITLOG_TYPE is still configured (removed setting)
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

    # Fail if AUDITLOG_TYPE is manually set in settings files (removed setting)
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
