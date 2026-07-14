from django import forms

from dojo.regulations.models import Regulation


class RegulationForm(forms.ModelForm):
    class Meta:
        model = Regulation
        exclude = ["product"]
