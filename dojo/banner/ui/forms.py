from django import forms
from django.utils.translation import gettext_lazy as _


class LoginBanner(forms.Form):
    banner_enable = forms.BooleanField(
        label=_("Enable login banner"),
        initial=False,
        required=False,
        help_text=_("Tick this box to enable a text banner on the login page"),
    )

    banner_message = forms.CharField(
        required=False,
        label=_("Message to display on the login page"),
    )

    def clean(self):
        return super().clean()
