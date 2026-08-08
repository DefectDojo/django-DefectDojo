from django import forms
from django.contrib import admin

from dojo.tool_config.models import Tool_Configuration


# declare form here as we can't import forms.py due to circular imports not even locally
class ToolConfigForm_Admin(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=False)
    api_key = forms.CharField(widget=forms.PasswordInput, required=False)
    ssh = forms.CharField(widget=forms.PasswordInput, required=False)

    # django doesn't seem to have an easy way to handle password fields as PasswordInput requires reentry of passwords
    password_from_db = None
    ssh_from_db = None
    api_key_from_db = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # keep password from db to use if the user entered no password
            self.password_from_db = self.instance.password
            self.ssh_from_db = self.instance.ssh
            self.api_key = self.instance.api_key

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data["password"] and not cleaned_data["ssh"] and not cleaned_data["api_key"]:
            cleaned_data["password"] = self.password_from_db
            cleaned_data["ssh"] = self.ssh_from_db
            cleaned_data["api_key"] = self.api_key_from_db

        return cleaned_data


class Tool_Configuration_Admin(admin.ModelAdmin):
    form = ToolConfigForm_Admin


admin.site.register(Tool_Configuration, Tool_Configuration_Admin)
