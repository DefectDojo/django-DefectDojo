from django import forms

from dojo.models import CICDInfrastructure


class CICDInfrastructureForm(forms.ModelForm):
    class Meta:
        model = CICDInfrastructure
        fields = ["name", "description", "url", "infrastructure_type"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            # Disallow editing of the infra type on an instance; engagement CICD FKs are scoped by infrastructure_type
            # via limit_choices_to (build_server/scm_server/orchestration), so changing the type would create a
            # semantic conflict between an engagement and this object.
            self.fields["infrastructure_type"].disabled = True
