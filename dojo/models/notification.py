from django.db import models
from django.utils.translation import gettext as _
from multiselectfield import MultiSelectField


NOTIFICATION_CHOICES = (
    ("slack", "slack"), ("msteams", "msteams"), ("mail", "mail"),
    ("alert", "alert")
)

DEFAULT_NOTIFICATION = ("alert", "alert")


class Notifications(models.Model):
    product_type_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    product_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    engagement_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    test_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)

    scan_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True, help_text=_('Triggered whenever an (re-)import has been done that created/updated/closed findings.'))
    jira_update = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True, verbose_name=_("JIRA problems"), help_text=_("JIRA sync happens in the background, errors will be shown as notifications/alerts so make sure to subscribe"))
    upcoming_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    stale_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    auto_close_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    close_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    user_mentioned = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    code_review = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    review_requested = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    other = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True)
    user = models.ForeignKey('Dojo_User', default=None, null=True, editable=False, on_delete=models.CASCADE)
    product = models.ForeignKey('Product', default=None, null=True, editable=False, on_delete=models.CASCADE)
    template = models.BooleanField(default=False)
    sla_breach = MultiSelectField(choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION, blank=True,
        verbose_name=_('SLA breach'),
        help_text=_('Get notified of (upcoming) SLA breaches'))
    risk_acceptance_expiration = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True,
        verbose_name=_('Risk Acceptance Expiration'),
        help_text=_('Get notified of (upcoming) Risk Acceptance expiries'))

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'product'], name="notifications_user_product")
        ]
        indexes = [
            models.Index(fields=['user', 'product']),
        ]

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
                # TODO This concat looks  better, but requires Python 3.6+
                # result.scan_added = [*result.scan_added, *notifications.scan_added]
                from dojo.utils import merge_sets_safe
                result.product_type_added = merge_sets_safe(result.product_type_added, notifications.product_type_added)
                result.product_added = merge_sets_safe(result.product_added, notifications.product_added)
                result.engagement_added = merge_sets_safe(result.engagement_added, notifications.engagement_added)
                result.test_added = merge_sets_safe(result.test_added, notifications.test_added)
                result.scan_added = merge_sets_safe(result.scan_added, notifications.scan_added)
                result.jira_update = merge_sets_safe(result.jira_update, notifications.jira_update)
                result.upcoming_engagement = merge_sets_safe(result.upcoming_engagement, notifications.upcoming_engagement)
                result.stale_engagement = merge_sets_safe(result.stale_engagement, notifications.stale_engagement)
                result.auto_close_engagement = merge_sets_safe(result.auto_close_engagement, notifications.auto_close_engagement)
                result.close_engagement = merge_sets_safe(result.close_engagement, notifications.close_engagement)
                result.user_mentioned = merge_sets_safe(result.user_mentioned, notifications.user_mentioned)
                result.code_review = merge_sets_safe(result.code_review, notifications.code_review)
                result.review_requested = merge_sets_safe(result.review_requested, notifications.review_requested)
                result.other = merge_sets_safe(result.other, notifications.other)
                result.sla_breach = merge_sets_safe(result.sla_breach, notifications.sla_breach)
                result.risk_acceptance_expiration = merge_sets_safe(result.risk_acceptance_expiration, notifications.risk_acceptance_expiration)

        return result


class Alerts(models.Model):
    title = models.CharField(max_length=250, default='', null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.URLField(max_length=2000, null=True, blank=True)
    source = models.CharField(max_length=100, default='Generic')
    icon = models.CharField(max_length=25, default='icon-user-check')
    user_id = models.ForeignKey('Dojo_User', null=True, editable=False, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, null=False)

    class Meta:
        ordering = ['-created']
