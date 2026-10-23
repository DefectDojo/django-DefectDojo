import importlib
import json
import logging
import re
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from datetime import timedelta

import crum
import requests
import yaml
from django.conf import settings
from django.core.exceptions import FieldDoesNotExist
from django.core.mail import EmailMessage, get_connection
from django.db import transaction
from django.db.models import Count, Prefetch, Q, QuerySet
from django.db.utils import InterfaceError, OperationalError
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
    Finding_Group,
    Product,
    Product_Type,
    System_Settings,
    Test,
    UserContactInfo,
    get_current_date,
    get_current_datetime,
)
from dojo.notifications.models import Alerts, Notification_Webhooks, Notifications
from dojo.notifications.render_cache import NotificationRenderCache
from dojo.user.queries import (
    get_authorized_users_for_product_and_product_type,
    get_authorized_users_for_product_type,
)

logger = logging.getLogger(__name__)

# Findings fetched per round trip by the daily SLA run, which streams them instead of
# holding every open finding in memory.
SLA_NOTIFY_CHUNK_SIZE = 2000

# Rows per INSERT when a notification's in-app alerts are written together.
ALERT_BULK_CREATE_BATCH_SIZE = 1000

# Mails sent over one SMTP session before it is closed and a new one opened. A fan-out
# reuses the session instead of connecting (and logging in) once per recipient, but stays
# within the per-session message limits mail servers commonly enforce (Exchange receive
# connectors default to 20). A relay with a lower limit, or one that drops an idle session,
# is covered by the retry in EmailNotificationManger._send_email.
MAIL_MESSAGES_PER_CONNECTION = 20


class MailConnectionBatch:

    """
    One mail connection shared by the messages of a fan-out.

    Opened on the first message, replaced every ``messages_per_connection`` messages, and
    dropped after a failed send so the next recipient starts a fresh session, as each did
    when every message opened its own.
    """

    def __init__(self, factory, messages_per_connection: int | None = None) -> None:
        self._factory = factory
        if messages_per_connection is None:
            messages_per_connection = MAIL_MESSAGES_PER_CONNECTION
        self._limit = max(1, messages_per_connection)
        self._connection = None
        self._sent = 0

    def connection(self):
        """The connection for the next message, opened if needed."""
        if self._connection is not None and self._sent >= self._limit:
            self.close()
        if self._connection is None:
            connection = self._factory()
            # Opened here rather than by send_messages(), which closes a connection it opened
            # itself after one message, and keeps one that was already open.
            connection.open()
            self._connection = connection
            self._sent = 0
        self._sent += 1
        return self._connection

    @property
    def reused(self) -> bool:
        """Whether the current message is not the first its connection carries."""
        return self._connection is not None and self._sent > 1

    def discard(self) -> None:
        """Drop the connection after a failed send; the next message opens a new one."""
        self.close()

    def close(self) -> None:
        connection, self._connection = self._connection, None
        if connection is None:
            return
        try:
            connection.close()
        except Exception:
            logger.exception("Unable to close the notification mail connection")


class AlertBuffer:

    """
    The in-app alerts of one fan-out, written in batches instead of one INSERT per recipient.

    Written every ``ALERT_BULK_CREATE_BATCH_SIZE`` alerts rather than only when the fan-out
    ends, so memory stays bounded and a worker stopped mid fan-out keeps what it had built. A
    failed INSERT costs that batch of alerts, except in a notification batch
    (NotificationManager.batch), where the rows are written again one at a time.
    """

    def __init__(self, write, *, auto_flush: bool = True) -> None:
        self._write = write
        self._pending: list = []
        # False when the owner decides when to write (see NotificationManager.batch).
        self._auto_flush = auto_flush

    def append(self, alert) -> None:
        self._pending.append(alert)
        if self._auto_flush and self.full():
            self.flush()

    def full(self) -> bool:
        return len(self._pending) >= ALERT_BULK_CREATE_BATCH_SIZE

    def flush(self) -> None:
        pending, self._pending = self._pending, []
        if pending:
            self._write(pending)


class WebhookOwners:

    """Which users own a webhook endpoint, read once per fan-out instead of once per recipient."""

    def __init__(self) -> None:
        self._owner_ids = None

    def has_endpoints(self, user: Dojo_User | None) -> bool:
        if self._owner_ids is None:
            self._owner_ids = set(Notification_Webhooks.objects.values_list("owner_id", flat=True).distinct())
        return (user.id if user is not None else None) in self._owner_ids


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


#: The manager of the notification batch open in this context, if any (see notification_batch).
_open_batch: ContextVar = ContextVar("notification_batch", default=None)


@contextmanager
def notification_batch():
    """
    Send every notification created inside the block through one manager.

    For a caller that creates one notification per object, such as the daily SLA run. Each
    notification is otherwise a fan-out of its own: a new manager reads the system
    notifications row, resolves the product's recipients and writes its alerts. In a batch
    those are read once, once per product, and in shared bulk INSERTs. Yields the manager,
    whose ``flush_alerts()`` writes the alerts collected so far once a full batch is waiting.
    """
    try:
        manager = get_manager_class_instance()
    except Exception:
        logger.exception("Unable to build the notification manager for a batch; sending each notification on its own")
        manager = None
    if not hasattr(manager, "batch"):
        # A custom NOTIFICATION_MANAGER that predates batching (or one that could not be built)
        # sends each notification on its own, as before.
        yield _UnbatchedNotifications()
        return
    with manager.batch():
        token = _open_batch.set(manager)
        try:
            yield manager
        finally:
            _open_batch.reset(token)


class _UnbatchedNotifications:

    """What notification_batch yields when it cannot batch: every notification goes out on its own."""

    def flush_alerts(self) -> None:
        pass


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
    (_open_batch.get() or get_manager_class_instance()).create_notification(
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

    #: Shared by every channel manager of one fan-out (see NotificationManager.create_notification):
    #: a message rendered for one recipient is reused for the next one that reads the same.
    #: None renders every message directly.
    render_cache: NotificationRenderCache | None = None

    def _create_notification_message(
        self,
        event: str,
        user: Dojo_User,
        notification_type: str,
        kwargs: dict,
    ) -> str:
        kwargs.update({"user": user})

        # TODO: This may be deleted
        # if (title := kwargs.get("title")) is not None:
        #     kwargs.update({"title": title})

        if kwargs.get("description") is None:
            kwargs.update({"description": self._create_description(event, kwargs)})

        if self.render_cache is None:
            return self._render_notification_message(event, notification_type, kwargs)
        return self.render_cache.render(
            self,
            event,
            notification_type,
            kwargs,
            lambda context: self._render_notification_message(event, notification_type, context),
        )

    def _render_notification_message(self, event: str, notification_type: str, kwargs: dict) -> str:
        template = f"notifications/{notification_type}/{event.replace('/', '')}.tpl"
        notification_message = None
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
        # This is the last-resort error logger for every notification channel, so it must
        # never raise: a failure to persist the Alert here would propagate out of the
        # notification pipeline and abort whatever triggered it (e.g. a scan import). The
        # persistence failure is logged and swallowed per superuser -- for instance when the
        # dojo_alerts primary-key sequence reaches its maximum, every save() fails, and
        # re-raising would take the import down with it.
        #
        # One INSERT for every superuser rather than one per superuser: a channel that
        # fails for each recipient calls this once per recipient, so a per-superuser
        # write (plus the foreign-key probe clean_fields ran for each) made a channel
        # outage cost recipients x superusers queries.
        alerts = []
        for user in Dojo_User.objects.filter(is_superuser=True):
            try:
                alert = Alerts(
                    user_id=user,
                    url=kwargs.get("url", reverse("alerts")),
                    title=kwargs.get("title", "Notification issue")[:250],
                    description=kwargs.get("description", str(exception))[:2000],
                    icon="exclamation-triangle",
                    source=notification_type[:100] if notification_type else kwargs.get("source", "unknown")[:100],
                )
                # relative urls will fail validation; the user was just read from the database
                alert.clean_fields(exclude=["url", "user_id"])
                alerts.append(alert)
            except Exception:
                logger.exception("Unable to build fallback Alert for user %s", user)
        if not alerts:
            return
        try:
            with transaction.atomic():
                Alerts.objects.bulk_create(alerts, batch_size=ALERT_BULK_CREATE_BATCH_SIZE)
        except Exception:
            logger.exception("Unable to persist fallback Alerts for %s superusers", len(alerts))


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
                            # The same user object can serve many notifications (a batch reuses
                            # its recipients), so keep the id on it too rather than looking it up again.
                            user.usercontactinfo.slack_user_id = slack_user_id
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

    #: The connection a fan-out's mails share (see NotificationManager.create_notification).
    #: None sends each message on its own connection.
    mail_batch: MailConnectionBatch | None = None

    def _new_mail_connection(self):
        """A new connection for a batch of notification mails."""
        return get_connection()

    def _mail_connection(self):
        """The shared connection for this message, or None for a connection of its own."""
        return self.mail_batch.connection() if self.mail_batch is not None else None

    def _discard_mail_connection(self) -> None:
        if self.mail_batch is not None:
            self.mail_batch.discard()

    def _send_email(self, email: EmailMessage) -> None:
        """
        Send one notification mail, on the fan-out's shared connection when there is one.

        A shared SMTP session can end under the message: the server caps messages per
        session, or drops a session that sat idle while a slow Slack or webhook call ran. So
        a send that fails on a connection that already carried a message is retried once on
        a new connection; only a failure there is the recipient's own.
        """
        try:
            email.send(fail_silently=False)
        except Exception:
            if self.mail_batch is None or not self.mail_batch.reused:
                raise
            logger.warning("Notification mail failed on a reused connection, retrying on a new one", exc_info=True)
            self.mail_batch.discard()
            email.connection = self.mail_batch.connection()
            email.send(fail_silently=False)

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

            body = self._create_notification_message(event, user, "mail", kwargs)
            email = EmailMessage(
                subject,
                body,
                self.system_settings.email_from,
                [address],
                headers={"From": f"{self.system_settings.email_from}"},
                connection=self._mail_connection(),
            )
            email.content_subtype = "html"
            logger.debug("sending email alert")
            self._send_email(email)

        except Exception as exception:
            self._discard_mail_connection()
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

    #: Endpoint owners, shared across a fan-out so a recipient without an endpoint costs no query.
    webhook_owners: WebhookOwners | None = None

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
        if (self.webhook_owners is not None and not self.webhook_owners.has_endpoints(user)) or not endpoints.exists():
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
        # The model default for header_name is "" (not None), so endpoints created
        # without a custom header via the API/ORM would add a header with an empty
        # name here, which requests rejects with InvalidHeader.
        if endpoint.header_name:
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

    #: When a NotificationManager fans one notification out to many recipients it
    #: hands every alert manager the same AlertBuffer, which collects the built alerts
    #: and writes them with one bulk INSERT per batch. None (a manager built on its own)
    #: writes each alert as it is built.
    alert_buffer: AlertBuffer | None = None

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
                # Only resolved when the caller gave no url: a default argument to get() is
                # evaluated on every call, once per recipient of a fan-out.
                url=kwargs["url"] if "url" in kwargs else reverse("alerts"),
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
            if self.alert_buffer is not None:
                self.alert_buffer.append(alert)
            else:
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
        # Every recipient's in-app alert is collected while the notification fans out and
        # written in bulk INSERTs of ALERT_BULK_CREATE_BATCH_SIZE (the rest when the fan-out
        # ends), instead of one INSERT per recipient. A nested call on the same manager
        # joins the outer batch.
        #
        # The other per-recipient costs are shared the same way for the duration of the
        # fan-out: each channel's message is rendered once and reused for every recipient
        # it reads the same for (NotificationRenderCache), the mails go out over one SMTP
        # session per batch instead of one per recipient, and webhook endpoint owners are
        # read once.
        if getattr(self, "_alert_buffer", None) is not None:
            if getattr(self, "_in_batch", False):
                # The notifications of a batch are about different objects, so each renders
                # its own messages rather than reusing another notification's.
                self._render_cache = NotificationRenderCache()
            self._create_notification(event, **kwargs)
            return
        self._open_fanout(kwargs)
        try:
            self._create_notification(event, **kwargs)
        finally:
            self._close_fanout()

    @contextmanager
    def batch(self):
        """
        Send many notifications through this manager as one fan-out (see notification_batch).

        The system notifications row was read when the manager was built, each product's
        recipients are resolved once, and the alerts of every notification share bulk INSERTs.
        Alerts are written only by ``flush_alerts()`` and when the batch ends, never in the
        middle of a notification, so a caller can keep each notification in its own savepoint
        without one notification's rollback erasing alerts written for the others.
        """
        if getattr(self, "_alert_buffer", None) is not None:
            msg = "A notification batch or fan-out is already open on this manager"
            raise RuntimeError(msg)
        self._open_fanout({}, auto_flush_alerts=False)
        self._in_batch = True
        self._recipients_by_scope = {}
        # Alert-write failures, tracked across the batch's flushes (see _write_alerts_one_at_a_time).
        self._alert_writes_given_up = False
        self._alert_failure_streak = 0
        self._alert_failure_notifications = set()
        self._alert_connection_failure_streak = 0
        self._alerts_not_written = 0
        self._last_alert_exception = None
        try:
            yield self
        finally:
            try:
                # Still a batch while its last alerts are written.
                self._close_fanout()
            finally:
                self._in_batch = False
                self._recipients_by_scope = None
                if self._alerts_not_written:
                    # One report for the whole batch, never one per row or per flush.
                    logger.error("%s alerts of this notification batch could not be written", self._alerts_not_written)
                    # Written exactly when the database has been refusing writes, so it can fail
                    # too; that must not escape the caller (or hide an exception already raised).
                    try:
                        self._log_alert(
                            self._last_alert_exception,
                            "Alert Notification",
                            description=f"{self._alerts_not_written} alerts could not be written: {self._last_alert_exception}",
                        )
                    except Exception:
                        logger.exception("Unable to report the alerts this notification batch could not write")

    def flush_alerts(self) -> None:
        """Write the alerts a batch has collected, once a full batch of them is waiting."""
        buffer = getattr(self, "_alert_buffer", None)
        if buffer is not None and buffer.full():
            buffer.flush()

    #: In a batch, how many single-row writes may fail in a row before the failure is taken to
    #: be the database's rather than one row's, and the rest of the alerts are given up.
    MAX_CONSECUTIVE_ALERT_FAILURES = 5

    def _write_alerts_one_at_a_time(self, alerts: list) -> None:
        """
        Write a batch's alerts one by one after their shared INSERT failed.

        A batch's alerts belong to many notifications, so one bad row, or one notification whose
        every row is bad, must not cost all the others. When rows of more than one notification
        fail in a row (across flushes too), the database is the problem rather than a row: the
        rest of the batch's alerts are given up instead of each being tried in turn. Everything
        not written is reported once, when the batch ends.
        """
        logger.warning("Writing %s alerts in one INSERT failed, writing them one at a time", len(alerts))
        logged_traceback = False
        for position, alert in enumerate(alerts):
            try:
                with transaction.atomic():
                    Alerts.objects.bulk_create([alert])
                self._alert_failure_streak = 0
                self._alert_failure_notifications.clear()
                self._alert_connection_failure_streak = 0
            except Exception as exception:
                # One traceback per flush; the rest of its failures are one line each.
                if logged_traceback:
                    logger.warning("Unable to create Alert Notification %r: %s", alert.title, exception)
                else:
                    logger.exception("Unable to create Alert Notification %r", alert.title)
                    logged_traceback = True
                self._alerts_not_written += 1
                self._last_alert_exception = exception
                self._alert_failure_streak += 1
                # One notification's alerts are adjacent and share its title and url.
                self._alert_failure_notifications.add((alert.title, alert.url))
                # A lost or refused connection is the database's fault whichever notification the
                # row belongs to; a data error (a bad value, a deleted user) may be just this one's.
                if isinstance(exception, (OperationalError, InterfaceError)):
                    self._alert_connection_failure_streak += 1
                else:
                    self._alert_connection_failure_streak = 0
                if self._alert_failure_streak >= self.MAX_CONSECUTIVE_ALERT_FAILURES and (
                    len(self._alert_failure_notifications) > 1
                    or self._alert_connection_failure_streak >= self.MAX_CONSECUTIVE_ALERT_FAILURES
                ):
                    remaining = len(alerts) - position - 1
                    self._alerts_not_written += remaining
                    self._alert_writes_given_up = True
                    logger.error("%s alert writes failed in a row, giving up the remaining %s and the rest of this batch", self._alert_failure_streak, remaining)
                    return

    def _open_fanout(self, kwargs: dict, *, auto_flush_alerts: bool = True) -> None:
        self._alert_buffer = AlertBuffer(lambda alerts: self._flush_alerts(alerts, kwargs), auto_flush=auto_flush_alerts)
        self._render_cache = NotificationRenderCache()
        self._mail_batch = MailConnectionBatch(lambda: self._get_manager_instance("mail")._new_mail_connection())
        self._webhook_owners = WebhookOwners()

    def _close_fanout(self) -> None:
        pending, self._alert_buffer = self._alert_buffer, None
        mail_batch, self._mail_batch = self._mail_batch, None
        self._render_cache = None
        self._webhook_owners = None
        mail_batch.close()
        pending.flush()

    def _flush_alerts(self, alerts: list, kwargs: dict) -> None:
        if not alerts:
            return
        if getattr(self, "_in_batch", False) and self._alert_writes_given_up:
            # The database refused alert after alert earlier in this batch; it was reported then.
            self._alerts_not_written += len(alerts)
            return
        try:
            # A savepoint, so a failed INSERT leaves the caller's transaction usable for
            # the fallback alert below and for whatever the caller does next.
            with transaction.atomic():
                Alerts.objects.bulk_create(alerts, batch_size=ALERT_BULK_CREATE_BATCH_SIZE)
        except Exception as exception:
            if getattr(self, "_in_batch", False) and len(alerts) > 1:
                self._write_alerts_one_at_a_time(alerts)
                return
            logger.exception("Unable to create %s Alert Notifications", len(alerts))
            details = {key: kwargs[key] for key in ("title", "url") if kwargs.get(key) is not None}
            self._log_alert(exception, "Alert Notification", description=str(exception), **details)

    def _create_notification(self, event: str | None = None, **kwargs: dict) -> None:
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
                for user in self._recipients_for_current_scope():
                    self._send_single_notification_to_user(user, event=event, **kwargs)

    def _process_recipients(self, event: str | None = None, **kwargs: dict) -> None:
        # mimic existing code so that when recipients is specified, no other system or personal notifications are sent.
        logger.debug("creating notifications for recipients: %s", kwargs["recipients"])
        # Callers pass usernames or Dojo_User instances; the lookup needs usernames.
        recipients = [getattr(recipient, "username", recipient) for recipient in kwargs["recipients"]]
        for recipient_notifications in self._get_recipient_notifications(recipients):
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

    def _get_recipient_notifications(self, recipients: list) -> QuerySet[Notifications]:
        """The global Notifications rows of the named, active recipients, with their user loaded."""
        return Notifications.objects.filter(
            user__username__in=recipients,
            user__is_active=True,
            product=None,
        ).select_related("user")

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

    def _recipients_for_current_scope(self):
        """The users to notify for the current product, resolved once per product in a batch."""
        cache = getattr(self, "_recipients_by_scope", None)
        if cache is None:
            return self._get_user_to_send_notifications_to()
        key = (getattr(self.product, "id", None), getattr(self.product_type, "id", None))
        if key not in cache:
            # A batch notifies one product's findings after another, so only the current
            # product's recipients are kept rather than every product's for the whole run.
            cache.clear()
            cache[key] = list(self._get_user_to_send_notifications_to())
        return cache[key]

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
        # A copy: in a batch the same user object is reused for every notification.
        applicable_notifications = list(user.applicable_notifications)
        if user.is_superuser and not applicable_notifications:
            # Superusers are included as recipients even with no notification
            # settings of their own, so fall back to the system defaults for them.
            # A superuser who *has* configured their own settings keeps them: the
            # merge below is a union, so folding the system row in would put its
            # channels back over anything they had switched off. Events that are
            # meant to override personal settings are handled by
            # NOTIFICATIONS_SYSTEM_LEVEL_TRUMP on the recipients path instead.
            logger.debug("User %s is superuser with no notification settings", user)
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
            return self._share_fanout_state(SlackNotificationManger(**kwargs))
        if alert_type == "msteams":
            return self._share_fanout_state(MSTeamsNotificationManger(**kwargs))
        if alert_type == "mail":
            return self._share_fanout_state(EmailNotificationManger(**kwargs))
        if alert_type == "webhooks":
            return self._share_fanout_state(WebhookNotificationManger(**kwargs))
        if alert_type == "alert":
            return self._share_fanout_state(AlertNotificationManger(**kwargs))

        msg = f"Unsupported alert type: {alert_type}"
        raise TypeError(msg)

    def _share_fanout_state(self, manager: NotificationManagerHelpers) -> NotificationManagerHelpers:
        """
        Hand a channel manager what this fan-out shares across recipients.

        Outside ``create_notification`` everything is None and the manager works on its own,
        exactly as before. A subclass that builds its own channel manager passes it through here.
        """
        manager.render_cache = getattr(self, "_render_cache", None)
        if isinstance(manager, AlertNotificationManger):
            manager.alert_buffer = getattr(self, "_alert_buffer", None)
        if isinstance(manager, EmailNotificationManger):
            manager.mail_batch = getattr(self, "_mail_batch", None)
        if isinstance(manager, WebhookNotificationManger):
            manager.webhook_owners = getattr(self, "_webhook_owners", None)
        return manager

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
        # They go straight to this manager's channel helpers with the recipient already loaded:
        # going through the send_*_notification task bodies re-read the user and rebuilt a
        # whole manager (system notifications row, system settings) per recipient per channel.
        if not alert_only:
            user = notifications.user
            if self.system_settings.enable_slack_notifications and "slack" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending Slack Notification")
                try:
                    self._get_manager_instance("slack").send_slack_notification(event, user=user, **kwargs)
                except Exception:
                    logger.exception("Failed to send Slack notification for event %s", event)

            if self.system_settings.enable_msteams_notifications and "msteams" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending MSTeams Notification")
                try:
                    self._get_manager_instance("msteams").send_msteams_notification(event, user=user, **kwargs)
                except Exception:
                    logger.exception("Failed to send MSTeams notification for event %s", event)

            if self.system_settings.enable_mail_notifications and "mail" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending Mail Notification")
                try:
                    self._get_manager_instance("mail").send_mail_notification(event, user=user, **kwargs)
                except Exception:
                    logger.exception("Failed to send Mail notification for event %s", event)

            if self.system_settings.enable_webhooks_notifications and "webhooks" in getattr(
                notifications,
                event,
                notifications.other,
            ):
                logger.debug("Sending Webhooks Notification")
                try:
                    self._get_manager_instance("webhooks").send_webhooks_notification(event, user=user, **kwargs)
                except Exception:
                    logger.exception("Failed to send Webhooks notification for event %s", event)


def process_tag_notifications(request, note, parent_url, parent_title, parent=None):
    # Django usernames may contain "@ . + - _" in addition to word characters (see
    # Django's username validators), so capture that whole set instead of only \w.
    # The leading (?:\A|\s)@ anchor keeps email addresses written in prose from
    # triggering, and trailing dots are stripped so a mention that ends a sentence
    # ("thanks @alice.") still resolves to the username.
    regex = re.compile(r"(?:\A|\s)@([\w.@+-]+)")

    usernames_to_check = {un.lower().rstrip(".") for un in regex.findall(note.entry)}

    users_to_notify = [
        Dojo_User.objects.filter(username=username).get()
        for username in usernames_to_check
        if Dojo_User.objects.filter(is_active=True, username=username).exists()
    ]
    if parent is not None:
        # Only users who can see the object the note is attached to get the mention.
        from dojo.authorization.authorization import user_has_permission  # noqa: PLC0415 -- lazy import, avoids circular dependency

        users_to_notify = [user for user in users_to_notify if user_has_permission(user, parent, "view")]

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
        recipients=[user.username for user in users_to_notify],
        requested_by=crum.get_current_user())


_NOTHING_READ = object()


def _read_sla_findings(findings, plain_findings):
    """
    Stream the SLA run's findings in chunks.

    ``findings`` is the query as FINDING_SLA_NOTIFY_QUERYSET_METHOD left it. A query that cannot
    be read at all (one that does not compile, a related name that does not exist, something that
    is not a query) only shows itself on the first chunk, so the first chunk is read here and, if
    that fails, the plain query is read instead. A failure on a later chunk is the caller's, as
    for the plain query.
    """
    if findings is plain_findings:
        yield from plain_findings.iterator(chunk_size=SLA_NOTIFY_CHUNK_SIZE)
        return
    try:
        chunks = findings.iterator(chunk_size=SLA_NOTIFY_CHUNK_SIZE)
        first = next(chunks, _NOTHING_READ)
    except Exception:
        logger.exception("Reading findings through FINDING_SLA_NOTIFY_QUERYSET_METHOD failed; reading them without it")
        yield from plain_findings.iterator(chunk_size=SLA_NOTIFY_CHUNK_SIZE)
        return
    if first is not _NOTHING_READ:
        yield first
        yield from chunks


def sla_compute_and_notify(*args, **kwargs):
    """
    The SLA computation and notification will be disabled if the user opts out
    of the Findings SLA on the System Settings page.

    Notifications are managed the usual way, so you'd have to opt-in.
    Exception is for JIRA issues, which would get a comment anyways.
    """
    from dojo.jira import services as jira_services  # noqa: PLC0415 circular import

    class NotificationEntry:
        def __init__(self, finding=None, jira_issue=None, jira_instance=None, *, do_jira_sla_comment=False):
            self.finding = finding
            self.jira_issue = jira_issue
            self.jira_instance = jira_instance
            self.do_jira_sla_comment = do_jira_sla_comment

    def _add_notification(finding, kind, jira_issue, jira_instance, *, do_jira_sla_comment):
        # kind can be one of: breached, prebreach, breaching
        if finding.test.engagement.product.disable_sla_breach_notifications:
            return

        notification = NotificationEntry(finding=finding,
                                         jira_issue=jira_issue,
                                         jira_instance=jira_instance,
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

    def _create_notifications(batch):
        # Alerts are written between notifications, outside their savepoints (see
        # NotificationManager.batch), so one notification's rollback cannot erase another's.
        for prodtype, comb_notif_prodtype in combined_notifications.items():
            for prod, comb_notif_prod in comb_notif_prodtype.items():
                for kind, comb_notif_kind in comb_notif_prod.items():
                    # creating notifications on per-finding basis

                    # we need this list for combined notification feature as we
                    # can not supply references to local objects as
                    # create_notification() arguments
                    findings_list = []

                    for n in comb_notif_kind:
                        findings_list.append(n.finding)
                        # one finding that cannot be notified must not stop the others; the
                        # savepoint keeps a database error here from aborting the run's transaction
                        title = None
                        try:
                            sla_age = n.finding.sla_days_remaining()
                            title = _notification_title_for_finding(n.finding, kind, sla_age)
                            with transaction.atomic():
                                create_notification(
                                    event="sla_breach",
                                    title=title,
                                    finding=n.finding,
                                    sla_age=sla_age,
                                    url=reverse("view_finding", args=(n.finding.id,)),
                                )
                        except Exception:
                            logger.exception("SLA notification failed for Finding %s, continuing with the next one", n.finding.id)
                        batch.flush_alerts()

                        # kept apart, so a JIRA failure does not undo the notification above
                        if n.do_jira_sla_comment and title:
                            try:
                                logger.info("Creating JIRA comment to notify of SLA breach information.")
                                jira_services.add_simple_comment(n.jira_instance, n.jira_issue, title)
                            except Exception:
                                logger.exception("JIRA SLA comment failed for Finding %s, continuing with the next one", n.finding.id)

                    # producing a "combined" SLA breach notification
                    try:
                        title_combined = f"SLA alert ({kind}): " + labels.ORG_WITH_NAME_LABEL % {"name": prodtype} + ", " + labels.ASSET_WITH_NAME_LABEL % {"name": prod}
                        product = comb_notif_kind[0].finding.test.engagement.product
                        with transaction.atomic():
                            create_notification(
                                event="sla_breach_combined",
                                title=title_combined,
                                product=product,
                                findings=findings_list,
                                breach_kind=kind,
                                base_url=get_script_prefix(),
                            )
                    except Exception:
                        logger.exception("Combined SLA notification failed for %s / %s (%s)", prodtype, prod, kind)
                    batch.flush_alerts()

    # exit early on flags
    system_settings = System_Settings.objects.get()
    if not system_settings.enable_notify_sla_active and not system_settings.enable_notify_sla_active_verified:
        logger.info("Will not notify on SLA breach per user configured settings")
        return

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

            if system_settings.enable_notify_sla_jira_only:
                logger.debug("Ignoring findings that are not linked to a JIRA issue")
                query &= Q(jira_issue__isnull=False)

            # Only a finding whose SLA ends between SLA_NOTIFY_POST_BREACH days ago and
            # SLA_NOTIFY_PRE_BREACH days from now can be notified, so leave the rest in the
            # database instead of evaluating every open finding in Python. A finding without an
            # expiration date is treated as breaching today below, and sla_days_remaining()
            # counts from the mitigated date when one is set, so both stay in.
            today = get_current_date()
            query &= (
                Q(sla_expiration_date__isnull=True)
                | Q(mitigated__isnull=False)
                | Q(
                    sla_expiration_date__gte=today - timedelta(days=settings.SLA_NOTIFY_POST_BREACH),
                    sla_expiration_date__lte=today + timedelta(days=settings.SLA_NOTIFY_PRE_BREACH),
                )
            )

            total_count = 0
            pre_breach_count = 0
            post_breach_count = 0
            post_breach_no_notify_count = 0
            jira_count = 0
            at_breach_count = 0
            error_count = 0

            # A finding with 'Info' severity will not be considered for SLA notifications (not in model)
            # Streamed in chunks; the prefetches share one Product (and its SLA configuration) per
            # chunk instead of loading it again for every finding.
            findings = Finding.objects \
                .filter(query) \
                .exclude(severity="Info") \
                .exclude(test__engagement__product__disable_sla_breach_notifications=True) \
                .select_related("jira_issue") \
                .prefetch_related(
                    "test__engagement__product__prod_type",
                    "test__engagement__product__sla_configuration",
                    Prefetch("finding_group_set", queryset=Finding_Group.objects.select_related("jira_issue")),
                )
            # A FINDING_SLA_PERIOD_METHOD can read more of each finding than is loaded above.
            # Its FINDING_SLA_NOTIFY_QUERYSET_METHOD adds that to the query, so it arrives with
            # each chunk instead of costing a query per finding.
            # A hook that cannot run must not cost the run: if calling it fails, or its query
            # cannot be read at all, the run reads its findings without it.
            from dojo.utils import get_custom_method  # noqa: PLC0415 circular import
            plain_findings = findings
            try:
                if queryset_method := get_custom_method("FINDING_SLA_NOTIFY_QUERYSET_METHOD"):
                    findings = queryset_method(findings)
            except Exception:
                logger.exception("FINDING_SLA_NOTIFY_QUERYSET_METHOD failed; reading findings without it")
            findings = _read_sla_findings(findings, plain_findings)

            # Whatever was collected before a failure to read further (a lost connection, say)
            # is still sent, rather than dropped along with the rest of the run.
            try:
                for finding in findings:
                    total_count += 1
                    # one finding that cannot be evaluated must not stop the run
                    try:
                        # a savepoint, so a database error on this finding cannot abort the
                        # transaction (if any) that the rest of the run depends on
                        with transaction.atomic():
                            # Finding.finding_group runs its own query; answer it from the prefetch
                            finding.finding_group = min(finding.finding_group_set.all(), key=lambda group: group.id, default=None)

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
                            jira_instance = None
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
                                    product_jira_sla_comment_enabled = False
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
                            kind = None
                            if (sla_age < 0):
                                post_breach_count += 1
                                logger.info(f"Finding {finding.id} has breached by {abs(sla_age)} days.")
                                abs_sla_age = abs(sla_age)
                                if not system_settings.enable_notify_sla_exponential_backoff or abs_sla_age == 1 or (abs_sla_age & (abs_sla_age - 1) == 0):
                                    kind = "breached"
                                else:
                                    logger.info("Skipping notification as exponential backoff is enabled and the SLA is not a power of two")
                            # The finding is within the pre-breach period
                            elif (sla_age > 0) and (sla_age <= settings.SLA_NOTIFY_PRE_BREACH):
                                pre_breach_count += 1
                                logger.info(f"Security SLA pre-breach warning for finding ID {finding.id}. Days remaining: {sla_age}")
                                kind = "prebreach"
                            # The finding breaches the SLA today
                            elif (sla_age == 0):
                                at_breach_count += 1
                                logger.info(f"Security SLA breach warning. Finding ID {finding.id} breaching today ({sla_age})")
                                kind = "breaching"

                            if kind:
                                _add_notification(finding, kind, jira_issue, jira_instance, do_jira_sla_comment=do_jira_sla_comment)
                    except Exception:
                        error_count += 1
                        logger.exception("SLA evaluation failed for Finding %s, continuing with the next one", finding.id)
            except Exception:
                logger.exception("SLA run stopped reading findings after %s; sending the notifications collected so far", total_count)

            # One manager for the whole run: the system notifications row is read once, each
            # product's recipients once, and the alerts go out in shared bulk INSERTs.
            with notification_batch() as batch:
                _create_notifications(batch)
            logger.info("SLA run results: Pre-breach: %s, at-breach: %s, post-breach: %s, post-breach-no-notify: %s, with-jira: %s, errors: %s, TOTAL: %s", pre_breach_count, at_breach_count, post_breach_count, post_breach_no_notify_count, jira_count, error_count, total_count)

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
