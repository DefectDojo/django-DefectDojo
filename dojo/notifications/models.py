from django.db import models
from django.utils.translation import gettext_lazy as _
from multiselectfield import MultiSelectField

NOTIFICATION_CHOICE_SLACK = ("slack", "slack")
NOTIFICATION_CHOICE_MSTEAMS = ("msteams", "msteams")
NOTIFICATION_CHOICE_MAIL = ("mail", "mail")
NOTIFICATION_CHOICE_WEBHOOKS = ("webhooks", "webhooks")
NOTIFICATION_CHOICE_ALERT = ("alert", "alert")

NOTIFICATION_CHOICES = (
    NOTIFICATION_CHOICE_SLACK,
    NOTIFICATION_CHOICE_MSTEAMS,
    NOTIFICATION_CHOICE_MAIL,
    NOTIFICATION_CHOICE_WEBHOOKS,
    NOTIFICATION_CHOICE_ALERT,
)

DEFAULT_NOTIFICATION = NOTIFICATION_CHOICE_ALERT


class Notifications(models.Model):
    product_type_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    product_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    engagement_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    test_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)

    scan_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True, help_text=_("Triggered whenever an (re-)import has been done that created/updated/closed findings."))
    scan_added_empty = MultiSelectField(choices=NOTIFICATION_CHOICES, default=[], blank=True, help_text=_("Triggered whenever an (re-)import has been done (even if that created/updated/closed no findings)."))
    jira_update = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True, verbose_name=_("JIRA problems"), help_text=_("JIRA sync happens in the background, errors will be shown as notifications/alerts so make sure to subscribe"))
    upcoming_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    stale_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    auto_close_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    close_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    user_mentioned = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    code_review = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    review_requested = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    other = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    user = models.ForeignKey("dojo.Dojo_User", default=None, null=True, editable=False, on_delete=models.CASCADE)
    product = models.ForeignKey("dojo.Product", default=None, null=True, editable=False, on_delete=models.CASCADE)
    template = models.BooleanField(default=False)
    sla_breach = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True,
        verbose_name=_("SLA breach"),
        help_text=_("Get notified of (upcoming) SLA breaches"))
    risk_acceptance_expiration = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True,
        verbose_name=_("Risk Acceptance Expiration"),
        help_text=_("Get notified of (upcoming) Risk Acceptance expiries"))
    sla_breach_combined = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True,
        verbose_name=_("SLA breach (combined)"),
        help_text=_("Get notified of (upcoming) SLA breaches (a message per project)"))

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "product"], name="notifications_user_product"),
        ]
        indexes = [
            models.Index(fields=["user", "product"]),
        ]

    def __str__(self):
        return f"Notifications about {self.product or 'all projects'} for {self.user or 'system notifications'}"

    @classmethod
    def merge_notifications_list(cls, notifications_list):
        if not notifications_list:
            return []

        result = None
        for notifications in notifications_list:
            if result is None:
                # we start by copying the first instance, because creating a new instance would set all notification columns to 'alert' :-()
                result = notifications
                # result.pk = None # detach from db
            else:
                result.product_type_added = {*result.product_type_added, *notifications.product_type_added}
                result.product_added = {*result.product_added, *notifications.product_added}
                result.engagement_added = {*result.engagement_added, *notifications.engagement_added}
                result.test_added = {*result.test_added, *notifications.test_added}
                result.scan_added = {*result.scan_added, *notifications.scan_added}
                result.jira_update = {*result.jira_update, *notifications.jira_update}
                result.upcoming_engagement = {*result.upcoming_engagement, *notifications.upcoming_engagement}
                result.stale_engagement = {*result.stale_engagement, *notifications.stale_engagement}
                result.auto_close_engagement = {*result.auto_close_engagement, *notifications.auto_close_engagement}
                result.close_engagement = {*result.close_engagement, *notifications.close_engagement}
                result.user_mentioned = {*result.user_mentioned, *notifications.user_mentioned}
                result.code_review = {*result.code_review, *notifications.code_review}
                result.review_requested = {*result.review_requested, *notifications.review_requested}
                result.other = {*result.other, *notifications.other}
                result.sla_breach = {*result.sla_breach, *notifications.sla_breach}
                result.sla_breach_combined = {*result.sla_breach_combined, *notifications.sla_breach_combined}
                result.risk_acceptance_expiration = {*result.risk_acceptance_expiration, *notifications.risk_acceptance_expiration}
        return result


class Notification_Webhooks(models.Model):
    class Status(models.TextChoices):
        __STATUS_ACTIVE = "active"
        __STATUS_INACTIVE = "inactive"
        STATUS_ACTIVE = f"{__STATUS_ACTIVE}", _("Active")
        STATUS_ACTIVE_TMP = f"{__STATUS_ACTIVE}_tmp", _("Active but 5xx (or similar) error detected")
        STATUS_INACTIVE_TMP = f"{__STATUS_INACTIVE}_tmp", _("Temporary inactive because of 5xx (or similar) error")
        STATUS_INACTIVE_PERMANENT = f"{__STATUS_INACTIVE}_permanent", _("Permanently inactive")

    name = models.CharField(max_length=100, default="", blank=False, unique=True,
                                    help_text=_("Name of the incoming webhook"))
    url = models.URLField(max_length=200, default="", blank=False,
                                    help_text=_("The full URL of the incoming webhook"))
    header_name = models.CharField(max_length=100, default="", blank=True, null=True,
                                   help_text=_("Name of the header required for interacting with Webhook endpoint"))
    header_value = models.CharField(max_length=100, default="", blank=True, null=True,
                                   help_text=_("Content of the header required for interacting with Webhook endpoint"))
    status = models.CharField(max_length=20, choices=Status, default="active", blank=False,
                              help_text=_("Status of the incoming webhook"), editable=False)
    first_error = models.DateTimeField(help_text=_("If endpoint is active, when error happened first time"), blank=True, null=True, editable=False)
    last_error = models.DateTimeField(help_text=_("If endpoint is active, when error happened last time"), blank=True, null=True, editable=False)
    note = models.CharField(max_length=1000, default="", blank=True, null=True, help_text=_("Description of the latest error"), editable=False)
    owner = models.ForeignKey("dojo.Dojo_User", editable=True, null=True, blank=True, on_delete=models.CASCADE,
                              help_text=_("Owner/receiver of notification, if empty processed as system notification"))
    # TODO: Test that `editable` will block editing via API


class Alerts(models.Model):
    title = models.CharField(max_length=250, default="", null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.URLField(max_length=2000, null=True, blank=True)
    source = models.CharField(max_length=100, default="Generic")
    icon = models.CharField(max_length=25, default="icon-user-check")
    user_id = models.ForeignKey("dojo.Dojo_User", null=True, editable=False, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, null=False)

    class Meta:
        ordering = ["-created"]
