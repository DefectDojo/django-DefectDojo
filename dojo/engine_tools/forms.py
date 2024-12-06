from django import forms
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.engine_tools.helpers import Constants


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
        help_text=Constants.VULNERABILITY_ID_HELP_TEXT.value)
    reason = forms.CharField(max_length=200, required=True,
                             widget=forms.Textarea,
                             label="Reason")

    class Meta:
        model = FindingExclusion
        exclude = [
            "uuid", 
            "product", 
            "user_history", 
            "created_by", 
            "accepted_by", 
            "status", 
            "finding", 
            "expiration_date",
            "status_updated_at",
            "status_updated_by",
            "reviewed_at",
            "final_status"
        ]
        

class FindingExclusionDiscussionForm(forms.ModelForm):
    class Meta:
        model = FindingExclusionDiscussion
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Add a comment...'})
        }
