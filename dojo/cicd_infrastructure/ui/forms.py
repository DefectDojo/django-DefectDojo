from django import forms

from dojo.models import CICDInfrastructure


class CICDInfrastructureForm(forms.ModelForm):
    class Meta:
        model = CICDInfrastructure
        fields = ["name", "description", "url", "infrastructure_type"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["infrastructure_type"].disabled = True
