from django import forms


class LoginBanner(forms.Form):
    banner_enable = forms.BooleanField(
        label="Enable login banner",
        initial=False,
        required=False,
        help_text="Tick this box to enable a text banner on the login page",
    )

    banner_message = forms.CharField(
        required=False,
        label="Message to display on the login page",
    )

    def clean(self):
        return super().clean()
