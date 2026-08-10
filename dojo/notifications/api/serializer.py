from django.core.exceptions import ValidationError
from rest_framework import serializers
from rest_framework.fields import MultipleChoiceField

from dojo.models import Dojo_User, Product
from dojo.notifications.models import (
    DEFAULT_NOTIFICATION,
    NOTIFICATION_CHOICES,
    Notification_Webhooks,
    Notifications,
)


class NotificationsSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    user = serializers.PrimaryKeyRelatedField(
        queryset=Dojo_User.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    product_type_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    product_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    engagement_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    test_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    scan_added = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    jira_update = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    upcoming_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    stale_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    auto_close_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    close_engagement = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    user_mentioned = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    code_review = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    review_requested = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    other = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    sla_breach = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    sla_breach_combined = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    risk_acceptance_expiration = MultipleChoiceField(
        choices=NOTIFICATION_CHOICES, default=DEFAULT_NOTIFICATION,
    )
    template = serializers.BooleanField(default=False)

    class Meta:
        model = Notifications
        fields = "__all__"

    def validate(self, data):
        user = None
        product = None
        template = False

        if self.instance is not None:
            user = self.instance.user
            product = self.instance.product

        if "user" in data:
            user = data.get("user")
        if "product" in data:
            product = data.get("product")
        if "template" in data:
            template = data.get("template")

        if (
            template
            and Notifications.objects.filter(template=True).count() > 0
        ):
            msg = "Notification template already exists"
            raise ValidationError(msg)
        if (
            self.instance is None
            or user != self.instance.user
            or product != self.instance.product
        ):
            notifications = Notifications.objects.filter(
                user=user, product=product, template=template,
            ).count()
            if notifications > 0:
                msg = "Notification for user and product already exists"
                raise ValidationError(msg)
        return data


class NotificationWebhooksSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification_Webhooks
        fields = "__all__"
