from django import forms
from dojo.models import Finding, Product, Dojo_User
from dojo.engine_tools.models import FindingExclusion


class FindingExclusionForm(forms.ModelForm):
    class Meta:
        model = FindingExclusion
        fields = "__all__"


class CreateFindingExclusionForm(forms.ModelForm):
    type = forms.ChoiceField(required=True,
                             choices=FindingExclusion.TYPE_CHOICES)
    unique_id_from_tool = forms.CharField(
        required=True,
        max_length=500,
        help_text="Vulnerability technical id from the source tool. Allows to track unique vulnerabilities.")
    expiration_date = forms.DateTimeField()
    user_history = forms.IntegerField(required=True)
    reason = forms.CharField(max_length=200, required=True,
                             widget=forms.Textarea,
                             label="Reason")

    class Meta:
        model = FindingExclusion
        exclude = ["product", "accepted_by", "status", "finding"]
