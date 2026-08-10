from django import forms
from django.core.validators import URLValidator

from dojo.tool_config.models import Tool_Configuration
from dojo.tool_type.models import Tool_Type


class ToolConfigForm(forms.ModelForm):
    tool_type = forms.ModelChoiceField(queryset=Tool_Type.objects.all(), label="Tool Type")
    ssh = forms.CharField(widget=forms.Textarea(attrs={}), required=False, label="SSH Key")
    # The credential columns are text so ciphertext of any length fits; keep the
    # single-line inputs a ModelForm would otherwise turn into textareas.
    password = forms.CharField(widget=forms.TextInput(attrs={}), required=False)
    api_key = forms.CharField(widget=forms.TextInput(attrs={}), required=False, label="API Key")

    class Meta:
        model = Tool_Configuration
        exclude = ["product"]

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
