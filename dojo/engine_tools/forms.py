from django import forms
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.engine_tools.helpers import Constants


class CreateFindingExclusionForm(forms.ModelForm):
    type = forms.ChoiceField(required=True,
                             choices=FindingExclusion.TYPE_CHOICES)
    unique_id_from_tool = forms.CharField(
        required=True,
        max_length=500,
        help_text=Constants.VULNERABILITY_ID_HELP_TEXT.value)
    reason = forms.CharField(max_length=200, required=True,
                             widget=forms.Textarea,
                             label="Reason",
                             help_text="Please provide a reason for excluding this vulnerability id.")
    
    practice = forms.CharField(required=False,
                                label="Practice Origin Exclusion",
                                help_text="practice where exclusion originates",)
    
    class Meta:
        model = FindingExclusion
        fields = ["type", "unique_id_from_tool", "reason", "practice"]
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.initial.get("practice"):
            self.fields.pop("practice")


class EditFindingExclusionForm(forms.ModelForm):

    class Meta:
        model = FindingExclusion
        fields = ["type", "unique_id_from_tool", "reason", "expiration_date", "status"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["expiration_date"].required = False
    
    
class FindingExclusionDiscussionForm(forms.ModelForm):
    class Meta:
        model = FindingExclusionDiscussion
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Add a comment...'})
        }
