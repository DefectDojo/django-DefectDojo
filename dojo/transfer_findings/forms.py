from django import forms
from dojo.models import TransferFinding

class DeleteTransferFindingForm(forms.ModelForm):
    id = forms.IntegerField(required=True, widget=forms.widgets.HiddenInput())

    class Meta:
        model = TransferFinding
        fields = ["id"]


class UpdateTransferFindingForm(forms.ModelForm):

    class Meta:
        model = TransferFinding
        fields = '__all__'
