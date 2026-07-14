from django import forms

from dojo.utils import get_system_setting


class ReportOptionsForm(forms.Form):
    yes_no = (("0", "No"), ("1", "Yes"))
    include_finding_notes = forms.ChoiceField(choices=yes_no, label="Finding Notes")
    include_finding_images = forms.ChoiceField(choices=yes_no, label="Finding Images")
    include_executive_summary = forms.ChoiceField(choices=yes_no, label="Executive Summary")
    include_table_of_contents = forms.ChoiceField(choices=yes_no, label="Table of Contents")
    include_disclaimer = forms.ChoiceField(choices=yes_no, label="Disclaimer")
    report_type = forms.ChoiceField(choices=(("HTML", "HTML"),))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if get_system_setting("disclaimer_reports_forced"):
            self.fields["include_disclaimer"].disabled = True
            self.fields["include_disclaimer"].initial = "1"  # represents yes
            self.fields["include_disclaimer"].help_text = "Administrator of the system enforced placement of disclaimer in all reports. You are not able exclude disclaimer from this report."


class CustomReportOptionsForm(forms.Form):
    yes_no = (("0", "No"), ("1", "Yes"))
    report_name = forms.CharField(required=False, max_length=100)
    include_finding_notes = forms.ChoiceField(required=False, choices=yes_no)
    include_finding_images = forms.ChoiceField(choices=yes_no, label="Finding Images")
    report_type = forms.ChoiceField(choices=(("HTML", "HTML"),))
