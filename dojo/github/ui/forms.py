from django import forms

from dojo.github.models import GITHUB_Conf, GITHUB_Issue, GITHUB_PKey


class GITHUB_IssueForm(forms.ModelForm):

    class Meta:
        model = GITHUB_Issue
        exclude = ["product"]


class GITHUBForm(forms.ModelForm):
    api_key = forms.CharField(widget=forms.PasswordInput, required=True)

    class Meta:
        model = GITHUB_Conf
        exclude = ["product"]


class DeleteGITHUBConfForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = GITHUB_Conf
        fields = ["id"]


class ExpressGITHUBForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    issue_key = forms.CharField(required=True, help_text="A valid issue ID is required to gather the necessary information.")

    class Meta:
        model = GITHUB_Conf
        exclude = ["product", "epic_name_id", "open_status_key",
                    "close_status_key", "info_mapping_severity",
                    "low_mapping_severity", "medium_mapping_severity",
                    "high_mapping_severity", "critical_mapping_severity", "finding_text"]


class GITHUB_Product_Form(forms.ModelForm):
    git_conf = forms.ModelChoiceField(queryset=GITHUB_Conf.objects.all(), label="GITHUB Configuration", required=False)

    class Meta:
        model = GITHUB_PKey
        exclude = ["product"]


class GITHUBFindingForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.enabled = kwargs.pop("enabled")
        super().__init__(*args, **kwargs)
        self.fields["push_to_github"] = forms.BooleanField()
        self.fields["push_to_github"].required = False
        self.fields["push_to_github"].help_text = "Checking this will overwrite content of your Github issue, or create one."

    push_to_github = forms.BooleanField(required=False)
