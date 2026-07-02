import importlib
import json
import logging
import re
from contextlib import suppress

import crum
import requests
import yaml
from django.conf import settings
from django.core.exceptions import FieldDoesNotExist
from django.core.mail import EmailMessage
from django.db.models import Count, Prefetch, Q, QuerySet
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.urls import get_script_prefix, reverse
from django.utils.translation import gettext as _

from dojo import __version__ as dd_version
from dojo.decorators import we_want_async
from dojo.labels import get_labels
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    System_Settings,
    Test,
    UserContactInfo,
    get_current_datetime,
)
from dojo.notifications.models import Alerts, Notification_Webhooks, Notifications
from dojo.user.queries import (
    get_authorized_users_for_product_and_product_type,
    get_authorized_users_for_product_type,
)

logger = logging.getLogger(__name__)


labels = get_labels()


def get_manager_class_instance():
    default_manager = NotificationManager
    notification_manager_class = default_manager
    if isinstance(
        (
            notification_manager := getattr(
                settings,
                "NOTIFICATION_MANAGER",
                default_manager,
            )
        ),
        str,
    ):
        with suppress(ModuleNotFoundError):
            module_name, _separator, class_name = notification_manager.rpartition(".")
            module = importlib.import_module(module_name)
            notification_manager_class = getattr(module, class_name)
    return notification_manager_class()


def create_notification(
    event: str | None = None,
    title: str | None = None,
    finding: Finding | None = None,
    test: Test | None = None,
    engagement: Engagement | None = None,
    product: Product | None = None,
    requested_by: Dojo_User | None = None,
    reviewers: list[Dojo_User] | list[str] | None = None,
    recipients: list[Dojo_User] | list[str] | None = None,
    no_users: bool = False,  # noqa: FBT001, FBT002
    url: str | None = None,
    url_api: str | None = None,
    alert_only: bool = False,  # noqa: FBT001, FBT002
    **kwargs: dict,
) -> None:
    """Create an instance of a NotificationManager and dispatch the notification."""
    get_manager_class_instance().create_notification(
        event=event,
        title=title,
        finding=finding,
        test=test,
        engagement=engagement,
        product=product,
        requested_by=requested_by,
        reviewers=reviewers,
        recipients=recipients,
        no_users=no_users,
        url=url,
        url_api=url_api,
        alert_only=alert_only,
        **kwargs,
    )


class NotificationManagerHelpers:

    """Common functions for use in the Mangers."""

    def __init__(
        self,
        *_args: list,
        system_notifications: Notifications | None = None,
        system_settings: System_Settings | None = None,
        **_kwargs: dict,
    ) -> None:
        self.system_notifications = system_notifications or self._get_notifications_object()
        self.system_settings = system_settings or self._get_system_settings()

    def _get_notifications_object(self) -> Notifications:
        """Set the system Notifications object on the class."""
        try:
            notifications, _ = Notifications.objects.get_or_create(
                user=None, product=None, template=False,
            )
        except Notifications.MultipleObjectsReturned:
            notifications = Notifications.objects.filter(
                user=None,
                product=None,
                template=False,
            ).first()
            logger.warning(
                "Multiple system notifications objects found, using the first one with id %s. Cleaning up the duplicate...",
                notifications.id,
            )
            Notifications.objects.filter(
                user=None,
                product=None,
                template=False,
            ).exclude(id=notifications.id).delete()
        return notifications

    def _get_system_settings(self) -> System_Settings:
        """Set the system settings object in the class."""
        return System_Settings.objects.get()

    def _create_description(self, event: str, kwargs: dict) -> str:
        if kwargs.get("description") is None:
            if event == "product_added":
                kwargs["description"] = labels.ASSET_NOTIFICATION_WITH_NAME_CREATED_MESSAGE % {"name": kwargs["title"]}
            elif event == "product_type_added":
                kwargs["description"] = labels.ORG_NOTIFICATION_WITH_NAME_CREATED_MESSAGE % {"name": kwargs["title"]}
            else:
                kwargs["description"] = _("Event %s has occurred.") % str(event)

        return kwargs["description"]

    def _create_notification_message(
        self,
        event: str,
        user: Dojo_User,
        notification_type: str,
        kwargs: dict,
    ) -> str:
        template = f"notifications/{notification_type}/{event.replace('/', '')}.tpl"
        kwargs.update({"user": user})
        notification_message = None

        # TODO: This may be deleted
        # if (title := kwargs.get("title")) is not None:
        #     kwargs.update({"title": title})

        if kwargs.get("description") is None:
            kwargs.update({"description": self._create_description(event, kwargs)})

        try:
            notification_message = render_to_string(template, kwargs)
            logger.debug("Rendering from the template %s", template)
        except TemplateDoesNotExist as e:
            # In some cases, template includes another templates, if the interior one is missing, we will see it in "specifically" section
            logger.debug(
                f"template not found or not implemented yet: {template} (specifically: {e.args})",
            )
        except Exception as e:
            logger.error(
                "error during rendering of template %s exception is %s",
                template,
                e,
            )
        finally:
            if not notification_message:
                kwargs["description"] = self._create_description(event, kwargs)
                notification_message = render_to_string(
                    f"notifications/{notification_type}/other.tpl",
                    kwargs,
                )

        return notification_message or ""

    def _log_alert(
        self,
        exception: Exception,
        notification_type: str | None = None,
        **kwargs: dict,
    ) -> None:
        # no try catch here, if this fails we need to show an error
        for user in Dojo_User.objects.filter(is_superuser=True):
            alert = Alerts(
                user_id=user,
                url=kwargs.get("url", reverse("alerts")),
                title=kwargs.get("title", "Notification issue")[:250],
                description=kwargs.get("description", str(exception))[:2000],
                icon="exclamation-triangle",
                source=notification_type[:100] if notification_type else kwargs.get("source", "unknown")[:100],
            )
            # relative urls will fail validation
            alert.clean_fields(exclude=["url"])
            alert.save()


class SlackNotificationManger(NotificationManagerHelpers):

    """Manger for slack notifications and their helpers."""

    def send_slack_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        try:
            # If the user has slack information on profile and chooses to receive slack notifications
            # Will receive a DM
            if user is not None:
                logger.debug("personal notification to slack for user %s", user)
                if hasattr(user, "usercontactinfo") and user.usercontactinfo.slack_username is not None:
                    slack_user_id = user.usercontactinfo.slack_user_id
                    if not slack_user_id:
                        # Lookup the slack userid the first time, then save it.
                        slack_user_id = self._get_slack_user_id(
                            user.usercontactinfo.slack_username,
                        )
                        if slack_user_id:
                            slack_user_save = UserContactInfo.objects.get(
                                user_id=user.id,
                            )
                            slack_user_save.slack_user_id = slack_user_id
                            slack_user_save.save()
                    # only send notification if we managed to find the slack_user_id
                    if slack_user_id:
                        channel = f"@{slack_user_id}"
                        self._post_slack_message(event, user, channel, **kwargs)
                else:
                    logger.info(
                        "The user %s does not have a email address informed for Slack in profile.",
                        user,
                    )
            # System scope slack notifications, and not personal would still see this go through
            elif self.system_settings.slack_channel is not None:
                channel = self.system_settings.slack_channel
                logger.info(
                    "Sending system notification to system channel %s.", channel,
                )
                self._post_slack_message(event, user, channel, **kwargs)
            else:
                logger.debug(
                    "slack_channel not configured: skipping system notification",
                )

        except Exception as exception:
            logger.exception("Unable to send Slack notification")
            self._log_alert(
                exception,
                "Slack Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs.get("url"),
            )

    def _get_slack_user_id(self, user_email: str) -> str:
        user_id = None
        res = requests.request(
            method="POST",
            url="https://slack.com/api/users.lookupByEmail",
            data={"token": self.system_settings.slack_token, "email": user_email},
            timeout=settings.REQUESTS_TIMEOUT,
        )

        user = json.loads(res.text)
        slack_user_is_found = False
        if user:
            if "error" in user:
                logger.error("Slack is complaining. See error message below.")
                logger.error(user)
                raise RuntimeError("Error getting user list from Slack: " + res.text)
            if "email" in user["user"]["profile"]:
                if user_email == user["user"]["profile"]["email"]:
                    if "id" in user["user"]:
                        user_id = user["user"]["id"]
                        logger.debug("Slack user ID is %s", user_id)
                        slack_user_is_found = True
                else:
                    logger.warning(
                        "A user with email %s could not be found in this Slack workspace.", user_email,
                    )

            if not slack_user_is_found:
                logger.warning("The Slack user was not found.")

        return user_id

    def _post_slack_message(
        self,
        event: str,
        user: Dojo_User,
        channel: str,
        **kwargs: dict,
    ) -> None:
        res = requests.request(
            method="POST",
            url="https://slack.com/api/chat.postMessage",
            data={
                "token": self.system_settings.slack_token,
                "channel": channel,
                "username": self.system_settings.slack_username,
                "text": self._create_notification_message(event, user, "slack", kwargs),
            },
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if "error" in res.text:
            logger.error("Slack is complaining. See raw text below.")
            logger.error(res.text)
            raise RuntimeError("Error posting message to Slack: " + res.text)


class MSTeamsNotificationManger(NotificationManagerHelpers):

    """Manger for Microsoft Teams notifications and their helpers."""

    def send_msteams_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        try:
            # Microsoft Teams doesn't offer direct message functionality, so no MS Teams PM functionality here...
            if user is None:
                if self.system_settings.msteams_url is not None:
                    logger.debug("sending MSTeams message")
                    res = requests.request(
                        method="POST",
                        url=self.system_settings.msteams_url,
                        data=self._create_notification_message(
                            event,
                            None,
                            "msteams",
                            kwargs,
                        ),
                        headers={"Content-Type": "application/json"},
                        timeout=settings.REQUESTS_TIMEOUT,
                    )
                    if not (200 <= res.status_code < 300):
                        logger.error("Error when sending message to Microsoft Teams")
                        logger.error(res.status_code)
                        logger.error(res.text)
                        raise RuntimeError(
                            "Error posting message to Microsoft Teams: " + res.text,
                        )
                else:
                    logger.info(
                        "Webhook URL for Microsoft Teams not configured: skipping system notification",
                    )
        except Exception as exception:
            logger.exception("Unable to send Microsoft Teams Notification")
            self._log_alert(
                exception,
                "Microsoft Teams Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs["url"],
            )


class EmailNotificationManger(NotificationManagerHelpers):

    """Manger for email notifications and their helpers."""

    def send_mail_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        # Attempt to get the "to" address
        if (recipient := kwargs.get("recipient")) is not None:
            address = recipient
        elif user:
            address = user.email
        else:
            address = self.system_settings.mail_notifications_to

        logger.debug("notification email for user %s to %s", user, address)

        try:
            subject = f"{self.system_settings.team_name} notification"
            if (title := kwargs.get("title")) is not None:
                subject += f": {title}"

            email = EmailMessage(
                subject,
                self._create_notification_message(event, user, "mail", kwargs),
                self.system_settings.email_from,
                [address],
                headers={"From": f"{self.system_settings.email_from}"},
            )
            email.content_subtype = "html"
            logger.debug("sending email alert")
            email.send(fail_silently=False)

        except Exception as exception:
            logger.exception("Unable to send Email Notification")
            self._log_alert(
                exception,
                "Email Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs["url"],
            )


class WebhookNotificationManger(NotificationManagerHelpers):

    """Manger for webhook notifications and their helpers."""

    ERROR_PERMANENT = "permanent"
    ERROR_TEMPORARY = "temporary"

    def send_webhooks_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        for endpoint in self._get_webhook_endpoints(user=user):
            error = None
            if endpoint.status not in {
                Notification_Webhooks.Status.STATUS_ACTIVE,
                Notification_Webhooks.Status.STATUS_ACTIVE_TMP,
            }:
                logger.info(
                    f"URL for Webhook '{endpoint.name}' is not active: {endpoint.get_status_display()} ({endpoint.status})",
                )
                continue

            try:
                logger.debug(f"Sending webhook message to endpoint '{endpoint.name}'")
                res = self._webhooks_notification_request(endpoint, event, **kwargs)
                if 200 <= res.status_code < 300:
                    logger.debug(
                        f"Message sent to endpoint '{endpoint.name}' successfully.",
                    )
                    continue
                # HTTP request passed successfully but we still need to check status code
                if 500 <= res.status_code < 600 or res.status_code == 429:
                    error = self.ERROR_TEMPORARY
                else:
                    error = self.ERROR_PERMANENT

                endpoint.note = f"Response status code: {res.status_code}"
                logger.error(
                    f"Error when sending message to Webhooks '{endpoint.name}' (status: {res.status_code}): {res.text}",
                )
            except requests.exceptions.Timeout as e:
                error = self.ERROR_TEMPORARY
                endpoint.note = f"Requests exception: {e}"
                logger.error(
                    f"Timeout when sending message to Webhook '{endpoint.name}'",
                )
            except Exception as exception:
                error = self.ERROR_PERMANENT
                endpoint.note = f"Exception: {exception}"[:1000]
                logger.exception("Unable to send Webhooks Notification")
                self._log_alert(exception, "Webhooks Notification")

            now = get_current_datetime()
            if error == self.ERROR_TEMPORARY:
                # If endpoint is unstable for more then one day, it needs to be deactivated
                if endpoint.first_error is not None and (now - endpoint.first_error).total_seconds() > 60 * 60 * 24:
                    endpoint.status = Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT
                else:
                    # We need to monitor when outage started
                    if endpoint.status == Notification_Webhooks.Status.STATUS_ACTIVE:
                        endpoint.first_error = now
                    endpoint.status = Notification_Webhooks.Status.STATUS_INACTIVE_TMP
                    # In case of failure within one day, endpoint can be deactivated temporally only for one minute
                    webhook_reactivation.apply_async(kwargs={"endpoint_id": endpoint.pk}, countdown=60)
            # There is no reason to keep endpoint active if it is returning 4xx errors
            else:
                endpoint.status = Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT
                endpoint.first_error = now

            endpoint.last_error = now
            endpoint.save()

    def _get_webhook_endpoints(
        self,
        user: Dojo_User | None = None,
    ) -> QuerySet[Notification_Webhooks]:
        endpoints = Notification_Webhooks.objects.filter(owner=user)
        if not endpoints.exists():
            if user:
                logger.info(
                    "URLs for Webhooks not configured for user '%s': skipping user notification", user,
                )
            else:
                logger.info(
                    "URLs for Webhooks not configured: skipping system notification",
                )
            return Notification_Webhooks.objects.none()
        return endpoints

    def _generate_request_details(
        self,
        endpoint: Notification_Webhooks,
        event: str | None = None,
        **kwargs: dict,
    ) -> tuple[dict, dict]:
        headers = {
            "User-Agent": f"DefectDojo-{dd_version}",
            "X-DefectDojo-Event": event,
            "X-DefectDojo-Instance": settings.SITE_URL,
            "Accept": "application/json",
        }
        if endpoint.header_name is not None:
            headers[endpoint.header_name] = endpoint.header_value
        yaml_data = self._create_notification_message(
            event,
            endpoint.owner,
            "webhooks",
            kwargs,
        )
        data = yaml.safe_load(yaml_data)

        return headers, data

    def _webhooks_notification_request(
        self,
        endpoint: Notification_Webhooks,
        event: str | None = None,
        **kwargs: dict,
    ) -> requests.Response:
        headers, data = self._generate_request_details(endpoint, event=event, **kwargs)
        return requests.request(
            method="POST",
            url=endpoint.url,
            headers=headers,
            json=data,
            timeout=self.system_settings.webhooks_notifications_timeout,
        )

    def _test_webhooks_notification(self, endpoint: Notification_Webhooks) -> None:
        res = self._webhooks_notification_request(
            endpoint,
            "ping",
            description="Test webhook notification",
        )
        res.raise_for_status()
        # in "send_webhooks_notification", we are doing deeper analysis, why it failed
        # for now, "raise_for_status" should be enough

    def _webhook_reactivation(self, endpoint_id: int, **_kwargs: dict):
        endpoint = Notification_Webhooks.objects.get(pk=endpoint_id)
        # User already changed status of endpoint
        if endpoint.status != Notification_Webhooks.Status.STATUS_INACTIVE_TMP:
            return
        endpoint.status = Notification_Webhooks.Status.STATUS_ACTIVE_TMP
        endpoint.save()
        logger.debug(
            f"Webhook endpoint '{endpoint.name}' reactivated to '{Notification_Webhooks.Status.STATUS_ACTIVE_TMP}'",
        )


class AlertNotificationManger(NotificationManagerHelpers):

    """Manger for alert notifications and their helpers."""

    def send_alert_notification(
        self,
        event: str,
        user: Dojo_User | None = None,
        **kwargs: dict,
    ):
        logger.debug("sending alert notification to %s", user)
        try:
            # no need to differentiate between user/no user
            icon = kwargs.get("icon", "info-circle")
            try:
                source = Notifications._meta.get_field(event).verbose_name.title()[:100]
            except FieldDoesNotExist:
                source = event.replace("_", " ").title()[:100]
            alert = Alerts(
                user_id=user,
                title=kwargs.get("title")[:250],
                description=self._create_notification_message(
                    event,
                    user,
                    "alert",
                    kwargs,
                )[:2000],
                url=kwargs.get("url", reverse("alerts")),
                icon=icon[:25],
                source=source,
            )
            # ``url`` skips validation (relative URLs are valid here but
            # URLField.validate rejects them). ``user_id`` skips the FK
            # existence probe — the user was just fetched from our own
            # DB by the caller, so the ``SELECT 1 FROM auth_user WHERE id=N
            # LIMIT 1`` round-trip every ForeignKey.validate would issue
            # is pure overhead at fan-out time.
            alert.clean_fields(exclude=["url", "user_id"])
            alert.save()
        except Exception as exception:
            logger.exception("Unable to create Alert Notification")
            self._log_alert(
                exception,
                "Alert Notification",
                title=kwargs["title"],
                description=str(exception),
                url=kwargs["url"],
            )


class NotificationManager(NotificationManagerHelpers):

    """Manage the construction and dispatch of notifications."""

    def __init__(self, *args: list, **kwargs: dict) -> None:
        NotificationManagerHelpers.__init__(self, *args, **kwargs)

    def create_notification(self, event: str | None = None, **kwargs: dict) -> None:
        # Process the notifications for a given list of recipients
        if kwargs.get("recipients") is not None:
            recipients = kwargs.get("recipients", [])
            if not recipients:
                logger.debug("No recipients provided for event: %s", event)
                return
            self._process_recipients(event=event, **kwargs)
        else:
            logger.debug("creating system notifications for event: %s", event)
            # send system notifications to all admin users
            self._process_objects(**kwargs)
            # System notifications are sent one with user=None, which will trigger email to configured system email, to global slack channel, etc.
            self._process_notifications(
                event,
                notifications=self.system_notifications,
                **kwargs,
            )
            # All admins will also receive system notifications, but as part of the person global notifications section below
            # This time user is set, so will trigger email to personal email, to personal slack channel (mention), etc.
            # only retrieve users which have at least one notification type enabled for this event type.
            logger.debug("creating personal notifications for event: %s", event)
            # There are notification like deleting a product type that shall not be sent to users.
            # These notifications will have the parameter no_users=True
            if kwargs.get("no_users", False) is False:
                # get users with either global notifications, or a product specific notification
                # and all admin/superuser, they will always be notified
                for user in self._get_user_to_send_notifications_to():
                    self._send_single_notification_to_user(user, event=event, **kwargs)

    def _process_recipients(self, event: str | None = None, **kwargs: dict) -> None:
        # mimic existing code so that when recipients is specified, no other system or personal notifications are sent.
        logger.debug("creating notifications for recipients: %s", kwargs["recipients"])
        for recipient_notifications in Notifications.objects.filter(
            user__username__in=kwargs["recipients"],
            user__is_active=True,
            product=None,
        ):
            if event in settings.NOTIFICATIONS_SYSTEM_LEVEL_TRUMP:
                # merge the system level notifications with the personal level
                # this allows for system to trump the personal
                merged_notifications = Notifications.merge_notifications_list(
                    [self.system_notifications, recipient_notifications],
                )
                merged_notifications.user = recipient_notifications.user
                logger.debug("Sent notification to %s", merged_notifications.user)
                self._process_notifications(
                    event,
                    notifications=merged_notifications,
                    **kwargs,
                )
            else:
                # Do not trump user preferences and send notifications as usual
                logger.debug("Sent notification to %s", recipient_notifications.user)
                self._process_notifications(
                    event,
                    notifications=recipient_notifications,
                    **kwargs,
                )

    def _process_objects(self, **kwargs: dict) -> None:
        """Extract the product and product type from the kwargs."""
        self.product_type: Product_Type = None
        self.product: Product = None
        if (product_type := kwargs.get("product_type")) is not None:
            self.product_type = product_type
            logger.debug("Defined product type %s", self.product_type)
        if (product := kwargs.get("product")) is not None:
            self.product = product
            logger.debug("Defined product  %s", self.product)
        elif (engagement := kwargs.get("engagement")) is not None:
            self.product = engagement.product
            logger.debug("Defined product of engagement %s", self.product)
        elif (test := kwargs.get("test")) is not None:
            self.product = test.engagement.product
            logger.debug("Defined product of test %s", self.product)
        elif (finding := kwargs.get("finding")) is not None:
            self.product = finding.test.engagement.product
            logger.debug("Defined product of finding %s", self.product)
        elif (obj := kwargs.get("obj")) is not None:
            from dojo.utils import get_product  # noqa: PLC0415 circular import
            self.product = get_product(obj)
            logger.debug("Defined product of obj %s", self.product)

    def _get_user_to_send_notifications_to(
        self,
    ) -> QuerySet[Dojo_User]:
        """Determine the users we should send notifications to based on product and product type permissions."""
        users = (
            Dojo_User.objects.filter(is_active=True)
            .prefetch_related(
                Prefetch(
                    "notifications_set",
                    queryset=Notifications.objects.filter(
                        Q(product_id=self.product) | Q(product__isnull=True),
                    ),
                    to_attr="applicable_notifications",
                ),
            )
            .annotate(
                applicable_notifications_count=Count(
                    "notifications__id",
                    filter=Q(notifications__product_id=self.product) | Q(notifications__product__isnull=True),
                ),
            )
            .filter(Q(applicable_notifications_count__gt=0) | Q(is_superuser=True))
        )
        # only send to authorized users or admin/superusers
        logger.debug("Filtering users for the product %s", self.product)
        if self.product is not None:
            users = get_authorized_users_for_product_and_product_type(
                users,
                self.product,
                "view",
            )
        elif self.product_type is not None:
            users = get_authorized_users_for_product_type(
                users,
                self.product_type,
                "view",
            )
        else:
            # nor product_type nor product defined, we should not make noise and send only notifications to admins
            logger.debug("Product is not specified, making it silent")
            users = users.filter(is_superuser=True)
        return users

    def _send_single_notification_to_user(
        self,
        user: Dojo_User,
        event: str | None = None,
        **kwargs: dict,
    ) -> None:
        """Send a notification to a single user."""
        logger.debug("Authorized user for the product %s", user)
        # send notifications to user after merging possible multiple notifications records (i.e. personal global + personal product)
        # kwargs.update({'user': user})
        applicable_notifications = user.applicable_notifications
        if user.is_superuser:
            # admin users get all system notifications
            logger.debug("User %s is superuser", user)
            applicable_notifications.append(self.system_notifications)

        notifications_set = Notifications.merge_notifications_list(
            applicable_notifications,
        )
        notifications_set.user = user
        self._process_notifications(event, notifications=notifications_set, **kwargs)

    def _get_manager_instance(
        self,
        alert_type: str,
    ) -> type[NotificationManagerHelpers]:
        kwargs = {
            "system_notifications": self.system_notifications,
            "system_settings": self.system_settings,
        }
        if alert_type == "slack":
            return SlackNotificationManger(**kwargs)
        if alert_type == "msteams":
            return MSTeamsNotificationManger(**kwargs)
        if alert_type == "mail":
            return EmailNotificationManger(**kwargs)
        if alert_type == "webhooks":
            return WebhookNotificationManger(**kwargs)
        if alert_type == "alert":
            return AlertNotificationManger(**kwargs)

        msg = f"Unsupported alert type: {alert_type}"
        raise TypeError(msg)

    def _process_notifications(
        self,
        event: str | None,
        notifications: Notifications | None = None,
        **kwargs: dict,
    ) -> None:
        # Quick break out if we do not have any work to do
        if not notifications:
            logger.warning("no notifications!")
            return

        # Lazy import to avoid circular import: dojo.notifications.tasks imports the
        # Manager classes defined in this module.

        logger.debug(
            "sending notification " + ("asynchronously" if we_want_async() else "synchronously"),
        )
        logger.debug("process notifications for %s", notifications.user)

        alert_only = kwargs.get("alert_only", False)
        if alert_only:
            logger.debug("sending alert only")

        if "alert" in getattr(notifications, event, notifications.other):
            logger.debug(f"Sending Alert to {notifications.user}")
            self._get_manager_instance("alert").send_alert_notification(
                event,
                user=notifications.user,
                **kwargs,
            )

        # Some errors should not be pushed to all channels, only to alerts.
        # For example reasons why JIRA Issues: https://github.com/DefectDojo/django-DefectDojo/issues/11575
        # Per-channel sends run synchronously inside the surrounding async_create_notification
        # task body. Dispatching inner Celery tasks would require JSON-serializable kwargs, but
        # callers pass model instances (finding/test/engagement/product/...) and refetching every
        # one of them per channel would multiply DB queries; running synchronously avoids both.
        if not alert_only:
            user_id = getattr(notifications.user, "id", None)
            if self.system_settings.enable_slack_notifications and "slack" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending Slack Notification")
                try:
                    send_slack_notification.run(event, user_id=user_id, **kwargs)
                except Exception:
                    logger.exception("Failed to send Slack notification for event %s", event)

            if self.system_settings.enable_msteams_notifications and "msteams" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending MSTeams Notification")
                try:
                    send_msteams_notification.run(event, user_id=user_id, **kwargs)
                except Exception:
                    logger.exception("Failed to send MSTeams notification for event %s", event)

            if self.system_settings.enable_mail_notifications and "mail" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending Mail Notification")
                try:
                    send_mail_notification.run(event, user_id=user_id, **kwargs)
                except Exception:
                    logger.exception("Failed to send Mail notification for event %s", event)

            if self.system_settings.enable_webhooks_notifications and "webhooks" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending Webhooks Notification")
                try:
                    send_webhooks_notification.run(event, user_id=user_id, **kwargs)
                except Exception:
                    logger.exception("Failed to send Webhooks notification for event %s", event)


def process_tag_notifications(request, note, parent_url, parent_title):
    regex = re.compile(r"(?:\A|\s)@(\w+)\b")

    usernames_to_check = set(un.lower() for un in regex.findall(note.entry))  # noqa: C401

    users_to_notify = [
        username
        for username in usernames_to_check
        if Dojo_User.objects.filter(is_active=True, username=username).exists()
    ]

    if len(note.entry) > 200:
        note.entry = note.entry[:200]
        note.entry += "..."

    create_notification(
        event="user_mentioned",
        section=parent_title,
        note=note,
        title=f"{request.user} jotted a note",
        url=parent_url,
        icon="commenting",
        recipients=users_to_notify,
        requested_by=crum.get_current_user())


def sla_compute_and_notify(*args, **kwargs):
    """
    The SLA computation and notification will be disabled if the user opts out
    of the Findings SLA on the System Settings page.

    Notifications are managed the usual way, so you'd have to opt-in.
    Exception is for JIRA issues, which would get a comment anyways.
    """
    from dojo.jira import services as jira_services  # noqa: PLC0415 circular import

    class NotificationEntry:
        def __init__(self, finding=None, jira_issue=None, *, do_jira_sla_comment=False):
            self.finding = finding
            self.jira_issue = jira_issue
            self.do_jira_sla_comment = do_jira_sla_comment

    def _add_notification(finding, kind):
        # jira_issue, do_jira_sla_comment are taken from the context
        # kind can be one of: breached, prebreach, breaching
        if finding.test.engagement.product.disable_sla_breach_notifications:
            return

        notification = NotificationEntry(finding=finding,
                                         jira_issue=jira_issue,
                                         do_jira_sla_comment=do_jira_sla_comment)

        pt = finding.test.engagement.product.prod_type.name
        p = finding.test.engagement.product.name

        if pt in combined_notifications:
            if p in combined_notifications[pt]:
                if kind in combined_notifications[pt][p]:
                    combined_notifications[pt][p][kind].append(notification)
                else:
                    combined_notifications[pt][p][kind] = [notification]
            else:
                combined_notifications[pt][p] = {kind: [notification]}
        else:
            combined_notifications[pt] = {p: {kind: [notification]}}

    def _notification_title_for_finding(finding, kind, sla_age):
        title = f"Finding {finding.id} - "
        if kind == "breached":
            abs_sla_age = abs(sla_age)
            period = "day"
            if abs_sla_age > 1:
                period = "days"
            title += f"SLA breached by {abs_sla_age} {period}! Overdue notice"
        elif kind == "prebreach":
            title += f"SLA pre-breach warning - {sla_age} day(s) left"
        elif kind == "breaching":
            title += "SLA is breaching today"

        return title

    def _create_notifications():
        for prodtype, comb_notif_prodtype in combined_notifications.items():
            for prod, comb_notif_prod in comb_notif_prodtype.items():
                for kind, comb_notif_kind in comb_notif_prod.items():
                    # creating notifications on per-finding basis

                    # we need this list for combined notification feature as we
                    # can not supply references to local objects as
                    # create_notification() arguments
                    findings_list = []

                    for n in comb_notif_kind:
                        sla_age = n.finding.sla_days_remaining()
                        title = _notification_title_for_finding(n.finding, kind, sla_age)
                        create_notification(
                            event="sla_breach",
                            title=title,
                            finding=n.finding,
                            sla_age=sla_age,
                            url=reverse("view_finding", args=(n.finding.id,)),
                        )

                        if n.do_jira_sla_comment:
                            logger.info("Creating JIRA comment to notify of SLA breach information.")
                            jira_services.add_simple_comment(jira_instance, n.jira_issue, title)

                        findings_list.append(n.finding)

                    # producing a "combined" SLA breach notification
                    title_combined = f"SLA alert ({kind}): " + labels.ORG_WITH_NAME_LABEL % {"name": prodtype} + ", " + labels.ASSET_WITH_NAME_LABEL % {"name": prod}
                    product = comb_notif_kind[0].finding.test.engagement.product
                    create_notification(
                        event="sla_breach_combined",
                        title=title_combined,
                        product=product,
                        findings=findings_list,
                        breach_kind=kind,
                        base_url=get_script_prefix(),
                    )

    # exit early on flags
    system_settings = System_Settings.objects.get()
    if not system_settings.enable_notify_sla_active and not system_settings.enable_notify_sla_active_verified:
        logger.info("Will not notify on SLA breach per user configured settings")
        return

    jira_issue = None
    jira_instance = None
    # notifications list per product per product type
    combined_notifications = {}
    try:
        if system_settings.enable_finding_sla:
            logger.info("About to process findings for SLA notifications.")
            logger.debug(f"Active {system_settings.enable_notify_sla_active}, Verified {system_settings.enable_notify_sla_active_verified}, Has JIRA {system_settings.enable_notify_sla_jira_only}, pre-breach {settings.SLA_NOTIFY_PRE_BREACH}, post-breach {settings.SLA_NOTIFY_POST_BREACH}")

            query = None
            if system_settings.enable_notify_sla_active_verified:
                query = Q(active=True, verified=True, is_mitigated=False, duplicate=False)
            elif system_settings.enable_notify_sla_active:
                query = Q(active=True, is_mitigated=False, duplicate=False)
            logger.debug("My query: %s", query)

            no_jira_findings = {}
            if system_settings.enable_notify_sla_jira_only:
                logger.debug("Ignoring findings that are not linked to a JIRA issue")
                no_jira_findings = Finding.objects.exclude(jira_issue__isnull=False)

            total_count = 0
            pre_breach_count = 0
            post_breach_count = 0
            post_breach_no_notify_count = 0
            jira_count = 0
            at_breach_count = 0

            # Taking away for now, since the prefetch is not efficient
            # .select_related('jira_issue') \
            # .prefetch_related(Prefetch('test__engagement__product__jira_project_set__jira_instance')) \
            # A finding with 'Info' severity will not be considered for SLA notifications (not in model)
            findings = Finding.objects \
                .filter(query) \
                .exclude(severity="Info") \
                .exclude(id__in=no_jira_findings)

            for finding in findings:
                total_count += 1
                sla_age = finding.sla_days_remaining()

                # get the sla enforcement for the severity and, if the severity setting is not enforced, do not notify
                # resolves an issue where notifications are always sent for the severity of SLA that is not enforced
                severity, enforce = finding.get_sla_period()
                if not enforce:
                    logger.debug(f"SLA is not enforced for Finding {finding.id} of {severity} severity, skipping notification.")
                    continue

                # if SLA is set to 0 in settings, it's a null. And setting at 0 means no SLA apparently.
                if sla_age is None:
                    sla_age = 0

                if (sla_age < 0) and (abs(sla_age) > settings.SLA_NOTIFY_POST_BREACH):
                    post_breach_no_notify_count += 1
                    # Skip finding notification if breached for too long
                    logger.debug(f"Finding {finding.id} breached the SLA {abs(sla_age)} days ago. Skipping notifications.")
                    continue

                do_jira_sla_comment = False
                jira_issue = None
                if finding.has_jira_issue:
                    jira_issue = finding.jira_issue
                elif finding.has_jira_group_issue:
                    jira_issue = finding.finding_group.jira_issue

                if jira_issue:
                    jira_count += 1
                    jira_instance = jira_services.get_instance(finding)
                    if jira_instance is not None:
                        logger.debug("JIRA config for finding is %s", jira_instance)
                        # global config or product config set, product level takes precedence
                        try:
                            # TODO: see new property from #2649 to then replace, somehow not working with prefetching though.
                            product_jira_sla_comment_enabled = jira_services.get_project(finding).product_jira_sla_notification
                        except Exception as e:
                            logger.error("The product is not linked to a JIRA configuration! Something is weird here.")
                            logger.error("Error is: %s", e)

                        jiraconfig_sla_notification_enabled = jira_instance.global_jira_sla_notification

                        if jiraconfig_sla_notification_enabled or product_jira_sla_comment_enabled:
                            logger.debug("Global setting %s -- Product setting %s", jiraconfig_sla_notification_enabled, product_jira_sla_comment_enabled)
                            do_jira_sla_comment = True
                            logger.debug(f"JIRA issue is {jira_issue.jira_key}")

                logger.debug(f"Finding {finding.id} has {sla_age} days left to breach SLA.")
                if (sla_age < 0):
                    post_breach_count += 1
                    logger.info(f"Finding {finding.id} has breached by {abs(sla_age)} days.")
                    abs_sla_age = abs(sla_age)
                    if not system_settings.enable_notify_sla_exponential_backoff or abs_sla_age == 1 or (abs_sla_age & (abs_sla_age - 1) == 0):
                        _add_notification(finding, "breached")
                    else:
                        logger.info("Skipping notification as exponential backoff is enabled and the SLA is not a power of two")
                # The finding is within the pre-breach period
                elif (sla_age > 0) and (sla_age <= settings.SLA_NOTIFY_PRE_BREACH):
                    pre_breach_count += 1
                    logger.info(f"Security SLA pre-breach warning for finding ID {finding.id}. Days remaining: {sla_age}")
                    _add_notification(finding, "prebreach")
                # The finding breaches the SLA today
                elif (sla_age == 0):
                    at_breach_count += 1
                    logger.info(f"Security SLA breach warning. Finding ID {finding.id} breaching today ({sla_age})")
                    _add_notification(finding, "breaching")

            _create_notifications()
            logger.info("SLA run results: Pre-breach: %s, at-breach: %s, post-breach: %s, post-breach-no-notify: %s, with-jira: %s, TOTAL: %s", pre_breach_count, at_breach_count, post_breach_count, post_breach_no_notify_count, jira_count, total_count)

    except System_Settings.DoesNotExist:
        logger.info("Findings SLA is not enabled.")


# Backward-compat re-exports: tasks moved to dojo.notifications.tasks. Placed at
# end-of-file so the Manager classes above are fully defined before
# dojo.notifications.tasks (which imports them) is loaded.
from dojo.notifications.tasks import (  # noqa: E402, F401  -- backward compat
    async_create_notification,
    send_mail_notification,
    send_msteams_notification,
    send_slack_notification,
    send_webhooks_notification,
    webhook_reactivation,
    webhook_status_cleanup,
)
