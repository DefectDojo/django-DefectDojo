import logging
from datetime import timedelta

from celery.utils.log import get_task_logger
from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from dojo.celery import app
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    System_Settings,
    Test,
    User,
    get_current_datetime,
)
from dojo.notifications.helper import (
    WebhookNotificationManger,
    create_notification,
    get_manager_class_instance,
    sla_compute_and_notify,
)
from dojo.notifications.models import Alerts, Notification_Webhooks

logger = get_task_logger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


# Logs the error to the alerts table, which appears in the notification toolbar
def log_generic_alert(source, title, description):
    create_notification(event="other", title=title, description=description,
                        icon="bullseye", source=source)


@app.task(bind=True)
def add_alerts(self, *args, **kwargs):
    # Run interval matches the beat schedule for this task (see CELERY_BEAT_SCHEDULE).
    runinterval = timedelta(hours=1)
    now = timezone.now()

    upcoming_engagements = Engagement.objects.filter(target_start__gt=now + timedelta(days=3), target_start__lt=now + timedelta(days=3) + runinterval).order_by("target_start")
    for engagement in upcoming_engagements:
        create_notification(event="upcoming_engagement",
                            title=f"Upcoming engagement: {engagement.name}",
                            engagement=engagement,
                            recipients=[engagement.lead],
                            url=reverse("view_engagement", args=(engagement.id,)))

    stale_engagements = Engagement.objects.filter(
        target_start__gt=now - runinterval,
        target_end__lt=now,
        status="In Progress").order_by("-target_end")
    for eng in stale_engagements:
        create_notification(event="stale_engagement",
                            title=f"Stale Engagement: {eng.name}",
                            description='The engagement "{}" is stale. Target end was {}.'.format(eng.name, eng.target_end.strftime("%b. %d, %Y")),
                            url=reverse("view_engagement", args=(eng.id,)),
                            recipients=[eng.lead])

    system_settings = System_Settings.objects.get()
    if system_settings.engagement_auto_close:
        # Close Engagements older than user defined days
        close_days = system_settings.engagement_auto_close_days
        unclosed_engagements = Engagement.objects.filter(target_end__lte=now - timedelta(days=close_days),
                                                        status="In Progress").order_by("target_end")

        for eng in unclosed_engagements:
            create_notification(event="auto_close_engagement",
                                title=eng.name,
                                description='The engagement "{}" has auto-closed. Target end was {}.'.format(eng.name, eng.target_end.strftime("%b. %d, %Y")),
                                url=reverse("view_engagement", args=(eng.id,)),
                                recipients=[eng.lead])

        unclosed_engagements.update(status="Completed", active=False, updated=timezone.now())

    # Calculate grade
    if system_settings.enable_product_grade:
        # Lazy import: dojo.utils imports create_notification from this module's
        # sibling (helper.py) at top-of-file, so importing dojo.utils eagerly here
        # creates a circular import during Django startup.
        from dojo.utils import calculate_grade  # noqa: PLC0415
        products = Product.objects.all()
        for product in products:
            dojo_dispatch_task(calculate_grade, product.id)


@app.task(bind=True)
def cleanup_alerts(*args, **kwargs):
    try:
        max_alerts_per_user = settings.MAX_ALERTS_PER_USER
    except System_Settings.DoesNotExist:
        max_alerts_per_user = -1

    if max_alerts_per_user > -1:
        total_deleted_count = 0
        logger.info("start deleting oldest alerts if a user has more than %s alerts", max_alerts_per_user)
        users = User.objects.all()
        for user in users:
            alerts_to_delete = Alerts.objects.filter(user_id=user.id).order_by("-created")[max_alerts_per_user:].values_list("id", flat=True)
            total_deleted_count += len(alerts_to_delete)
            Alerts.objects.filter(pk__in=list(alerts_to_delete)).delete()
        logger.info("total number of alerts deleted: %s", total_deleted_count)


@app.task
def async_sla_compute_and_notify_task(*args, **kwargs):
    logger.debug("Computing SLAs and notifying as needed")
    try:
        system_settings = System_Settings.objects.get()
        if system_settings.enable_finding_sla:
            sla_compute_and_notify(*args, **kwargs)
    except Exception:
        logger.exception("An unexpected error was thrown calling the SLA code")


@app.task
def send_slack_notification(event: str, user_id: int | None = None, **kwargs: dict) -> None:
    user = Dojo_User.objects.get(pk=user_id) if user_id else None
    get_manager_class_instance()._get_manager_instance("slack").send_slack_notification(event, user=user, **kwargs)


@app.task
def send_msteams_notification(event: str, user_id: int | None = None, **kwargs: dict) -> None:
    user = Dojo_User.objects.get(pk=user_id) if user_id else None
    get_manager_class_instance()._get_manager_instance("msteams").send_msteams_notification(event, user=user, **kwargs)


@app.task
def send_mail_notification(event: str, user_id: int | None = None, **kwargs: dict) -> None:
    user = Dojo_User.objects.get(pk=user_id) if user_id else None
    get_manager_class_instance()._get_manager_instance("mail").send_mail_notification(event, user=user, **kwargs)


@app.task
def send_webhooks_notification(event: str, user_id: int | None = None, **kwargs: dict) -> None:
    user = Dojo_User.objects.get(pk=user_id) if user_id else None
    get_manager_class_instance()._get_manager_instance("webhooks").send_webhooks_notification(event, user=user, **kwargs)


@app.task
def async_create_notification(
    event: str,
    engagement_id: int | None = None,
    product_id: int | None = None,
    product_type_id: int | None = None,
    finding_id: int | None = None,
    test_id: int | None = None,
    **kwargs: dict,
) -> None:
    # Re-fetch by id so the recipient-enumeration query and per-user Alert writes
    # run in the worker rather than the request thread.
    # Fetch most-specific first and derive parent objects from the already-loaded
    # select_related chain to avoid redundant queries. For example, fetching a
    # Test with select_related("engagement__product") covers all three objects in
    # one query, so engagement_id and product_id don't need separate fetches.
    fetched_engagement = None
    fetched_product = None

    if test_id is not None:
        test = Test.objects.filter(pk=test_id).select_related("engagement__product").first()
        if test is None:
            return
        kwargs["test"] = test
        fetched_engagement = test.engagement
        fetched_product = test.engagement.product

    if engagement_id is not None:
        if fetched_engagement is not None:
            kwargs["engagement"] = fetched_engagement
        else:
            engagement = Engagement.objects.filter(pk=engagement_id).select_related("product").first()
            if engagement is None:
                return
            kwargs["engagement"] = engagement
            fetched_product = engagement.product

    if product_id is not None:
        if fetched_product is not None:
            kwargs["product"] = fetched_product
        else:
            product = Product.objects.filter(pk=product_id).first()
            if product is None:
                return
            kwargs["product"] = product

    if product_type_id is not None:
        product_type = Product_Type.objects.filter(pk=product_type_id).first()
        if product_type is None:
            return
        kwargs["product_type"] = product_type

    if finding_id is not None:
        finding = Finding.objects.filter(pk=finding_id).select_related("test__engagement__product").first()
        if finding is None:
            return
        kwargs["finding"] = finding

    # Resolve via the helper module so unit tests that patch
    # `dojo.notifications.helper.create_notification` capture this call.
    from dojo.notifications import helper as _notifications_helper  # noqa: PLC0415
    _notifications_helper.create_notification(event=event, **kwargs)


@app.task(ignore_result=True)
def webhook_reactivation(endpoint_id: int, **_kwargs: dict) -> None:
    get_manager_class_instance()._get_manager_instance("webhooks")._webhook_reactivation(endpoint_id=endpoint_id)


@app.task(ignore_result=True)
def webhook_status_cleanup(*_args: list, **_kwargs: dict):
    # If some endpoint was affected by some outage (5xx, 429, Timeout) but it was clean during last 24 hours,
    # we consider this endpoint as healthy so need to reset it
    endpoints = Notification_Webhooks.objects.filter(
        status=Notification_Webhooks.Status.STATUS_ACTIVE_TMP,
        last_error__lt=get_current_datetime() - timedelta(hours=24),
    )
    for endpoint in endpoints:
        endpoint.status = Notification_Webhooks.Status.STATUS_ACTIVE
        endpoint.first_error = None
        endpoint.last_error = None
        endpoint.note = f"Reactivation from {Notification_Webhooks.Status.STATUS_ACTIVE_TMP}"
        endpoint.save()
        logger.debug(
            f"Webhook endpoint '{endpoint.name}' reactivated from '{Notification_Webhooks.Status.STATUS_ACTIVE_TMP}' to '{Notification_Webhooks.Status.STATUS_ACTIVE}'",
        )

    # Reactivation of STATUS_INACTIVE_TMP endpoints.
    # They should reactive automatically in 60s, however in case of some unexpected event (e.g. start of whole stack),
    # endpoints should not be left in STATUS_INACTIVE_TMP state
    broken_endpoints = Notification_Webhooks.objects.filter(
        status=Notification_Webhooks.Status.STATUS_INACTIVE_TMP,
        last_error__lt=get_current_datetime() - timedelta(minutes=5),
    )
    for endpoint in broken_endpoints:
        manager = WebhookNotificationManger()
        manager._webhook_reactivation(endpoint_id=endpoint.pk)
