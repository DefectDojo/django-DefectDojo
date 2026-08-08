from django import forms
from django.core.validators import URLValidator

from dojo.tool_config.models import Tool_Configuration
from dojo.tool_product.models import Tool_Product_Settings


class DeleteToolProductSettingsForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Tool_Product_Settings
        fields = ["id"]


class ToolProductSettingsForm(forms.ModelForm):
    tool_configuration = forms.ModelChoiceField(queryset=Tool_Configuration.objects.all(), label="Tool Configuration")

    class Meta:
        model = Tool_Product_Settings
        fields = ["name", "description", "url", "tool_configuration", "tool_project_id"]
        exclude = ["tool_type"]
        order = ["name"]

    def clean(self):
        form_data = self.cleaned_data

        try:
            if form_data["url"] is not None:
                url_validator = URLValidator(schemes=["ssh", "http", "https"])
                url_validator(form_data["url"])
        except forms.ValidationError:
            msg = "It does not appear as though this endpoint is a valid URL/SSH or IP address."
            raise forms.ValidationError(msg, code="invalid")

        return form_data
