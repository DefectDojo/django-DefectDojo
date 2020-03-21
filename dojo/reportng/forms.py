from django import forms


class ReportNGBuilderControlForm(forms.Form):
    """
    Hidden form used to track the current state of the builder page.
    """

    step = forms.IntegerField(min_value=1, max_value=5, widget=forms.HiddenInput())
    build = forms.BooleanField(widget=forms.HiddenInput())
    save_draft = forms.BooleanField(widget=forms.HiddenInput())
    overwrite_draft = forms.BooleanField(
        initial=True, required=False, label="Overwrite this draft"
    )
