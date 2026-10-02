from django import forms

from dojo.labels import get_labels
from dojo.system_settings.models import System_Settings

labels = get_labels()


class SystemSettingsForm(forms.ModelForm):
    jira_webhook_secret = forms.CharField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["enable_product_tracking_files"].label = labels.SETTINGS_TRACKED_FILES_ENABLE_LABEL
        self.fields["enable_product_tracking_files"].help_text = labels.SETTINGS_TRACKED_FILES_ENABLE_HELP

        self.fields[
            "enforce_verified_status_product_grading"].label = labels.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_LABEL
        self.fields[
            "enforce_verified_status_product_grading"].help_text = labels.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_HELP

        self.fields["enable_product_grade"].label = labels.SETTINGS_ASSET_GRADING_ENABLE_LABEL
        self.fields["enable_product_grade"].help_text = labels.SETTINGS_ASSET_GRADING_ENABLE_HELP

        self.fields["enable_product_tag_inheritance"].label = labels.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_LABEL
        self.fields["enable_product_tag_inheritance"].help_text = labels.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_HELP

    def clean(self):
        cleaned_data = super().clean()
        enable_jira_value = cleaned_data.get("enable_jira")
        jira_webhook_secret_value = cleaned_data.get("jira_webhook_secret").strip()

        if enable_jira_value and not jira_webhook_secret_value:
            self.add_error("jira_webhook_secret", "This field is required when enable Jira Integration is True")

        return cleaned_data

    class Meta:
        model = System_Settings
        exclude = ()
