"""
Audit logging configuration for DefectDojo.

This module handles conditional registration of models with either django-auditlog
or django-pghistory based on the DD_AUDITLOG_TYPE setting.
"""
import contextlib
import logging
import sys

import pghistory
from django.conf import settings
from django.core.management import call_command
from django.db import models

logger = logging.getLogger(__name__)


def enable_django_auditlog():
    """Enable django-auditlog by registering models."""
    # Import inside function to avoid AppRegistryNotReady errors
    from auditlog.registry import auditlog  # noqa: PLC0415

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

    logger.info("Enabling django-auditlog: Registering models")
    auditlog.register(Dojo_User, exclude_fields=["password"])
    auditlog.register(Endpoint)
    auditlog.register(Engagement)
    auditlog.register(Finding, m2m_fields={"reviewers"})
    auditlog.register(Finding_Group)
    auditlog.register(Product_Type)
    auditlog.register(Product)
    auditlog.register(Test)
    auditlog.register(Risk_Acceptance)
    auditlog.register(Finding_Template)
    auditlog.register(Cred_User, exclude_fields=["password"])
    auditlog.register(Notification_Webhooks, exclude_fields=["header_name", "header_value"])
    logger.info("Successfully enabled django-auditlog")


def disable_django_auditlog():
    """Disable django-auditlog by unregistering models."""
    # Import inside function to avoid AppRegistryNotReady errors
    from auditlog.registry import auditlog  # noqa: PLC0415

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
        logger.info("Django-auditlog disabled - unregistering models")

    # Unregister all models from auditlog
    models_to_unregister = [
        Dojo_User, Endpoint, Engagement, Finding, Finding_Group,
        Product_Type, Product, Test, Risk_Acceptance, Finding_Template,
        Cred_User, Notification_Webhooks,
    ]

    for model in models_to_unregister:
        with contextlib.suppress(Exception):
            # Model might not be registered, ignore the error
            auditlog.unregister(model)


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

    # Only log during actual application startup, not during shell commands
    if "shell" not in sys.argv:
        logger.info("Successfully registered models with django-pghistory")


def enable_django_pghistory():
    """Enable django-pghistory by enabling triggers."""
    logger.info("Enabling django-pghistory: Enabling triggers")

    # Enable pghistory triggers
    try:
        call_command("pgtrigger", "enable")
        logger.info("Successfully enabled pghistory triggers")
    except Exception as e:
        logger.warning(f"Failed to enable pgtrigger triggers: {e}")
        # Don't raise the exception as this shouldn't prevent Django from starting


def disable_django_pghistory():
    """Disable django-pghistory by disabling triggers."""
    logger.info("Disabling django-pghistory: Disabling triggers")
    try:
        call_command("pgtrigger", "disable")
        logger.info("Successfully disabled pghistory triggers")
    except Exception as e:
        logger.warning(f"Failed to disable pgtrigger triggers: {e}")
        # Don't raise the exception as this shouldn't prevent Django from starting


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
    elif settings.AUDITLOG_TYPE == "django-pghistory":
        try:
            call_command("pgtrigger", "enable")
            logger.info("Successfully enabled pghistory triggers")
        except Exception as e:
            logger.error(f"Failed to enable pghistory triggers: {e}")
            raise
    else:
        try:
            call_command("pgtrigger", "disable")
            logger.info("Successfully disabled pghistory triggers")
        except Exception as e:
            logger.error(f"Failed to disable pghistory triggers: {e}")
            raise


def configure_audit_system():
    """
    Configure the audit system based on settings.

    Note: This function only handles auditlog registration. pghistory model registration
    is handled in apps.py, and trigger management should be done via the
    configure_pghistory_triggers() function to avoid database access during initialization.
    """
    # Only log during actual application startup, not during shell commands
    log_enabled = "shell" not in sys.argv

    if not settings.ENABLE_AUDITLOG:
        if log_enabled:
            logger.info("Audit logging disabled")
        disable_django_auditlog()
        return

    if settings.AUDITLOG_TYPE == "django-auditlog":
        if log_enabled:
            logger.info("Configuring audit system: django-auditlog enabled")
        enable_django_auditlog()
    else:
        if log_enabled:
            logger.info("django-auditlog disabled (pghistory or other audit type selected)")
        disable_django_auditlog()
