from django import forms

from dojo.notifications.models import Notification_Webhooks, Notifications


class NotificationsForm(forms.ModelForm):

    class Meta:
        model = Notifications
        exclude = ["template"]


class NotificationsWebhookForm(forms.ModelForm):
    class Meta:
        model = Notification_Webhooks
        exclude = []

    def __init__(self, *args, **kwargs):
        is_superuser = kwargs.pop("is_superuser", False)
        super().__init__(*args, **kwargs)
        if not is_superuser:  # Only superadmins can edit owner
            self.fields["owner"].disabled = True  # TODO: needs to be tested


class DeleteNotificationsWebhookForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["name"].disabled = True
        self.fields["url"].disabled = True

    class Meta:
        model = Notification_Webhooks
        fields = ["id", "name", "url"]


class ProductNotificationsForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.id:
            self.initial["engagement_added"] = ""
            self.initial["close_engagement"] = ""
            self.initial["test_added"] = ""
            self.initial["scan_added"] = ""
            self.initial["sla_breach"] = ""
            self.initial["sla_breach_combined"] = ""
            self.initial["risk_acceptance_expiration"] = ""

    class Meta:
        model = Notifications
        fields = ["engagement_added", "close_engagement", "test_added", "scan_added", "sla_breach", "sla_breach_combined", "risk_acceptance_expiration"]
