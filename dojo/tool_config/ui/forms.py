from django import forms
from django.core.validators import URLValidator

from dojo.tool_config.models import Tool_Configuration
from dojo.tool_type.models import Tool_Type


class ToolConfigForm(forms.ModelForm):
    # Stored values are never sent back to the browser. A blank submission means
    # "unchanged", which dojo.tool_config.ui.views applies on save.
    CREDENTIAL_FIELDS = ("password", "ssh", "api_key")

    tool_type = forms.ModelChoiceField(queryset=Tool_Type.objects.all(), label="Tool Type")
    password = forms.CharField(widget=forms.PasswordInput, required=False, max_length=900)
    ssh = forms.CharField(widget=forms.Textarea(attrs={}), required=False, label="SSH Key")
    api_key = forms.CharField(widget=forms.PasswordInput, required=False, max_length=900, label="API Key")

    class Meta:
        model = Tool_Configuration
        exclude = ["product"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.CREDENTIAL_FIELDS:
            self.initial[field] = ""

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
