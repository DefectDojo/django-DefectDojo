import logging
from pathlib import Path

from dateutil.relativedelta import relativedelta
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone

from dojo.finding.queries import get_authorized_findings
from dojo.models import Finding, Risk_Acceptance
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)


class EditRiskAcceptanceForm(forms.ModelForm):
    # unfortunately django forces us to repeat many things here. choices, default, required etc.
    recommendation = forms.ChoiceField(choices=Risk_Acceptance.TREATMENT_CHOICES, initial=Risk_Acceptance.TREATMENT_ACCEPT, widget=forms.RadioSelect, label="Security Recommendation")
    decision = forms.ChoiceField(choices=Risk_Acceptance.TREATMENT_CHOICES, initial=Risk_Acceptance.TREATMENT_ACCEPT, widget=forms.RadioSelect)

    path = forms.FileField(label="Proof", required=False, widget=forms.widgets.FileInput(attrs={"accept": ", ".join(settings.FILE_IMPORT_TYPES)}))
    expiration_date = forms.DateTimeField(required=False, widget=forms.TextInput(attrs={"class": "datepicker"}))

    class Meta:
        model = Risk_Acceptance
        exclude = ["accepted_findings", "notes"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["path"].help_text = f"Existing proof uploaded: {self.instance.filename()}" if self.instance.filename() else "None"
        self.fields["expiration_date_warned"].disabled = True
        self.fields["expiration_date_handled"].disabled = True

    def clean_path(self):
        if (data := self.cleaned_data.get("path")) is not None:
            ext = Path(data.name).suffix  # [0] returns path+filename
            valid_extensions = settings.FILE_UPLOAD_TYPES
            if ext.lower() not in valid_extensions:
                if accepted_extensions := f"{', '.join(valid_extensions)}":
                    msg = f"Unsupported extension. Supported extensions are as follows: {accepted_extensions}"
                else:
                    msg = "File uploads are prohibited due to the list of acceptable file extensions being empty"
                raise ValidationError(msg)
        return data


class RiskAcceptanceForm(EditRiskAcceptanceForm):
    accepted_findings = forms.ModelMultipleChoiceField(
        queryset=Finding.objects.none(), required=True,
        widget=forms.widgets.SelectMultiple(attrs={"size": 10}),
        help_text=("Active, verified findings listed, please select to add findings."))
    notes = forms.CharField(required=False, max_length=2400,
                            widget=forms.Textarea,
                            label="Notes")

    class Meta:
        model = Risk_Acceptance
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        expiration_delta_days = get_system_setting("risk_acceptance_form_default_days")
        logger.debug("expiration_delta_days: %i", expiration_delta_days)
        if expiration_delta_days > 0:
            expiration_date = timezone.now().date() + relativedelta(days=expiration_delta_days)
            # logger.debug('setting default expiration_date: %s', expiration_date)
            self.fields["expiration_date"].initial = expiration_date
        # self.fields['path'].help_text = 'Existing proof uploaded: %s' % self.instance.filename() if self.instance.filename() else 'None'
        self.fields["accepted_findings"].queryset = get_authorized_findings("edit")
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()


class ReplaceRiskAcceptanceProofForm(forms.ModelForm):
    path = forms.FileField(label="Proof", required=True, widget=forms.widgets.FileInput(attrs={"accept": ".jpg,.png,.pdf"}))

    class Meta:
        model = Risk_Acceptance
        fields = ["path"]
