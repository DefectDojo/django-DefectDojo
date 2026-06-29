from django import forms

from dojo.object.models import Objects_Product


class DeleteObjectsSettingsForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Objects_Product
        fields = ["id"]


class ObjectSettingsForm(forms.ModelForm):

    class Meta:
        model = Objects_Product
        fields = ["path", "folder", "artifact", "name", "review_status", "tags"]
        exclude = ["product"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data
